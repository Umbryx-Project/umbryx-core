# mythic-container's syncPayloadData reads UI icons from /usr/src/app/static/
# (the path baked into the official sandbox layout) — provide them so payload
# sync does not loop forever on a missing file.
FROM umbryx/mythic-apollo:latest
COPY static /usr/src/app/static
