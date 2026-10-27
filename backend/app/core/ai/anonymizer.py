"""Reversible anonymization of data sent to LLM providers.

Red-team concern: external AI providers must not learn the engagement's
real identifiers. Outgoing conversation text is tokenized (IPs, hostnames,
FQDNs, domain\\user principals, emails, bare domains → [IP_1], [HOST_2],
[USER_1] …); the mapping lives ONLY in this process (per chat run) and is
applied in reverse to everything the model produces — streamed content,
final answer, tool-call arguments — so the operator sees real values and
tools execute against real targets, while the wire carries tokens.

Anonymization is ON by default for every provider (credential store
field `anonymize`, opt-out): the wire must carry tokens unless an admin
explicitly trusts a fully local endpoint and disables it.
"""

import re

_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# DOMAIN\user (also works for user@domain handled by email first)
_PRINCIPAL_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9._-]{1,30})\\([A-Za-z][A-Za-z0-9._$-]{1,40})\b")
# FQDN: label(.label)+ with an alpha TLD-ish tail or known internal zones
_FQDN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,6}"
    r"(?:local|corp|lan|internal|intra|arpa|com|net|org|io|dev|test|ru|su|eu|ai|co|me|xyz|info|biz)\b"
)
# bare internal-looking domains: corp.local, ad.company (no public TLD)
_BARE_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]{2,20}\.){1,2}(?:local|corp|lan|internal)\b")

_TOKEN_RE = re.compile(r"\[(IP|HOST|USER|EMAIL|DOMAIN)_([0-9]{1,4})\]")

_KINDS = ("IP", "HOST", "USER", "EMAIL", "DOMAIN")


class Anonymizer:
    """Per-run token map. Not thread-safe by design (one run = one instance)."""

    def __init__(self):
        self._map: dict[str, str] = {}  # real → token
        self._rev: dict[str, str] = {}  # token → real
        self._counters = {k: 0 for k in _KINDS}
        # streaming hold-back: tail of a chunk that may be a split token
        self._pending = ""

    # ── outgoing ──────────────────────────────────────────────────────
    def anonymize(self, text: str) -> str:
        if not text:
            return text

        def _tok(kind: str, real: str) -> str:
            if real not in self._map:
                self._counters[kind] += 1
                token = f"[{kind}_{self._counters[kind]}]"
                self._map[real] = token
                self._rev[token] = real
            return self._map[real]

        out = text
        # order matters: emails before principals/FQDNs (they contain them),
        # principals before FQDNs (DOMAIN\host part may match FQDN)
        out = _EMAIL_RE.sub(lambda m: _tok("EMAIL", m.group(0)), out)
        out = _PRINCIPAL_RE.sub(lambda m: _tok("USER", m.group(0)), out)
        out = _IPV4_RE.sub(lambda m: _tok("IP", m.group(0)), out)
        out = _FQDN_RE.sub(lambda m: _tok("HOST", m.group(0)), out)
        out = _BARE_DOMAIN_RE.sub(lambda m: _tok("DOMAIN", m.group(0)), out)
        return out

    def anonymize_messages(self, messages: list) -> list:
        """Tokenize an outgoing conversation: message contents AND tool-call
        arguments (the protocol shape — roles, tool_calls, tool_call_id —
        is preserved as-is; dropping tool_calls would break the OpenAI
        tool protocol)."""
        import dataclasses

        out = []
        for m in messages:
            content = getattr(m, "content", None)
            tool_calls = getattr(m, "tool_calls", None)
            new_content = self.anonymize(content) if isinstance(content, str) and content else content
            new_tcs = None
            if tool_calls:
                new_tcs = []
                for tc in tool_calls:
                    tc_data = tc.model_dump() if hasattr(tc, "model_dump") else vars(tc)
                    tc_data["arguments"] = self._anon_args(tc_data.get("arguments"))
                    # Reconstruct the ORIGINAL tool-call class: providers
                    # call tc.to_openai_dict() later, and a bare dict crashes
                    # the second LLM round with an AttributeError (found live:
                    # every anonymized multi-round agent run died right after
                    # its first tool call).
                    try:
                        new_tcs.append(type(tc)(**tc_data))
                    except Exception:  # noqa: BLE001 — exotic shapes keep the dict
                        new_tcs.append(tc_data)
            if dataclasses.is_dataclass(m):
                out.append(
                    dataclasses.replace(m, content=new_content, tool_calls=new_tcs or tool_calls)
                )
            elif hasattr(m, "model_dump"):
                data = m.model_dump()
                data["content"] = new_content
                if new_tcs is not None:
                    data["tool_calls"] = new_tcs
                out.append(type(m).model_validate(data))
            else:
                out.append(m)
        return out

    def _anon_args(self, args):
        if isinstance(args, dict):
            return {k: self._anon_args(v) for k, v in args.items()}
        if isinstance(args, list):
            return [self._anon_args(v) for v in args]
        if isinstance(args, str):
            return self.anonymize(args)
        return args

    # ── incoming (model → user/tools) ────────────────────────────────
    def restore(self, text: str) -> str:
        if not text:
            return text
        # longest tokens first: [HOST_10] before [HOST_1]
        for token in sorted(self._rev, key=len, reverse=True):
            if token in text:
                text = text.replace(token, self._rev[token])
        return text

    def restore_stream_chunk(self, chunk: str) -> str:
        """Restore a streamed chunk, holding back a possibly split token tail.

        A token like [IP_12] may arrive split across SSE chunks; the tail
        is held until the next chunk completes or proves it's not a token.
        Flush remainder with flush() at stream end."""
        data = self._pending + chunk
        self._pending = ""
        # does the chunk end mid-token? ("[IP_1" / "[HO")
        m = re.search(r"\[[A-Z]{0,6}(?:_[0-9]{0,4})?$", data)
        if m:
            self._pending = m.group(0)
            data = data[: m.start()]
        return self.restore(data)

    def flush(self) -> str:
        tail, self._pending = self._pending, ""
        return self.restore(tail)

    def restore_args(self, args: dict) -> dict:
        """De-tokenize tool-call arguments recursively before execution."""
        if isinstance(args, dict):
            return {k: self.restore_args(v) for k, v in args.items()}
        if isinstance(args, list):
            return [self.restore_args(v) for v in args]
        if isinstance(args, str):
            return self.restore(args)
        return args

    @property
    def active(self) -> bool:
        return bool(self._map)
