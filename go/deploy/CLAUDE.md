# Rules for AI
- All text, ASCII, and code files MUST end with a newline.
- All environment variables **MUST** follow the format UNKEY_<SERVICE_NAME>_VARNAME
- **Always** prioritize reliability over performance.
- Use `make install` to test, build, and install the binary w/systemd unit from `$SERVICE/contrib/systemd`
- When a service's `*.go` code changes significantly, increase the patch-level version number.

# Service folder structure

The root implied here is `deploy/`

- Systemd unit files etc: `<service>/contrib/systemd`
- Build artifact directory: `<service>/build`
- Service-level makefile: `<service>/Makefile`
- Global makefile: `Makefile`
- Service binary code: `<service>/cmd/<service | command>`

# Service Pillars

Four services make up the pillars of "Unkey Deploy"

- assetmanagerd
- billaged
- builderd
- metald

# SIFFE/Spire

Spire handles mTLS for all service communication
