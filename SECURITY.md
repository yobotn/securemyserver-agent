# 🔐 Security policy

This repository is the SecureMyServer agent. It runs as root on customer servers, so we take reports about it
seriously.

## 📨 Report a vulnerability

Email **security@securemyserver.com**, or use GitHub's "Report a vulnerability" button on this repository
(private advisory). Please include what you found, how to reproduce it, and the agent version
(`securemyserver version`).

Please don't open a public issue for a security problem, and give us a reasonable time to fix it before you
publish. We'll confirm we received your report, keep you updated, and credit you if you want.

The full policy, including what is in scope and our safe-harbour promise, is at
<https://securemyserver.com/security>.

## 🎯 What we especially want to hear about

- Any way to make the agent run a command or write a file that isn't one of the signed safe switches, the signed
  blocklist or a passkey-signed session undo.
- Any way to get a switch, blocklist or undo accepted without the owner's passkey signature, or without
  `securemyserver allow` on the server.
- Any way for the agent to send secrets, private keys, file contents or shell history upward.
- Any way to get the agent to listen on a port.

## ✅ Verify a release

Every release has `SHA256SUMS` signed with our minisign key:

```
RWQx+6u8bOlqJNGa4Pmh2fmgzY+imJCjE9WDQlpWkNY6T+eZQjoTfDCk
```

Paste on your server or laptop, in the folder holding the downloads:

```
minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P RWQx+6u8bOlqJNGa4Pmh2fmgzY+imJCjE9WDQlpWkNY6T+eZQjoTfDCk
sha256sum -c --ignore-missing SHA256SUMS
```
