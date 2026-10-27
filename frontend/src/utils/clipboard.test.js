import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { copyToClipboard } from './clipboard.js';

describe('copyToClipboard', () => {
  const originalClipboard = navigator.clipboard;
  const originalSecure = window.isSecureContext;

  afterEach(() => {
    Object.defineProperty(navigator, 'clipboard', { value: originalClipboard, configurable: true });
    Object.defineProperty(window, 'isSecureContext', { value: originalSecure, configurable: true });
    vi.restoreAllMocks();
  });

  it('uses navigator.clipboard.writeText in a secure context', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });

    await copyToClipboard('hello');
    expect(writeText).toHaveBeenCalledWith('hello');
  });

  it('falls back to execCommand when navigator.clipboard is unavailable (plain HTTP)', async () => {
    // The Clipboard API only exists in a secure context (HTTPS or
    // localhost) — an airgap/on-prem install reached over plain HTTP via
    // its real hostname/IP has navigator.clipboard === undefined here,
    // which is exactly the case every copy button in the app hit.
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true });
    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;

    await copyToClipboard('fallback-text');
    expect(execCommand).toHaveBeenCalledWith('copy');
  });

  it('falls back to execCommand when isSecureContext is false even if clipboard exists', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true });
    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;

    await copyToClipboard('x');
    expect(writeText).not.toHaveBeenCalled();
    expect(execCommand).toHaveBeenCalledWith('copy');
  });

  it('rejects when the fallback execCommand fails', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    Object.defineProperty(window, 'isSecureContext', { value: false, configurable: true });
    document.execCommand = vi.fn().mockReturnValue(false);

    await expect(copyToClipboard('nope')).rejects.toThrow();
  });

  it('rejects for nullish input without touching the clipboard', async () => {
    const writeText = vi.fn();
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });

    await expect(copyToClipboard(undefined)).rejects.toThrow();
    expect(writeText).not.toHaveBeenCalled();
  });
});
