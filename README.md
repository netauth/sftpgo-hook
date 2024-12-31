# sftpgo-hook

This is a hook as described in the SFTPGo documentation for [external
authentication](https://github.com/drakkan/sftpgo/blob/main/docs/external-auth.md)
that allows you to validate your SFTPGo users via NetAuth.

It can be enabled by configuring the following environment variables:

```
SFTPGO_DATA_PROVIDER__EXTERNAL_AUTH_HOOK=/absolute/path/to/sftpgo-hook
SFTPGO_COMMAND__COMMANDS__0__PATH=/absolute/path/to/sftpgo-hook
SFTPGO_COMMAND__COMMANDS__0__ENV=SFTPGO_NETAUTH_REQUIREGROUP=optional-group,SFTPGO_NETAUTH_HOMEDIR=/base/path/for/netauth/users
SFTPGO_COMMAND__COMMANDS__0__HOOK=external_auth
```
