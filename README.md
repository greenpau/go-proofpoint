# go-proofpoint

<a href="https://github.com/greenpau/go-proofpoint/actions/" target="_blank"><img src="https://github.com/greenpau/go-proofpoint/workflows/build/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/go-proofpoint" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>

Proofpoint API Client Library

<!-- begin-markdown-toc -->
## Table of Contents

* [Getting Started](#getting-started)
* [References](#references)

<!-- end-markdown-toc -->

## Getting Started

First, install `ppcli`:

```bash
go get -u github.com/greenpau/go-proofpoint/cmd/ppcli
```

Next, set environment variables for Proofpoint API Service Principal:

```bash
export PROOFPOINT_SERVICE_PRINCIPAL=8c5e8866-0062-4059-b2be-92707e4374da
export PROOFPOINT_PRINCIPAL_SECRET=f982025ecbaa8c42bec8b19c98c3ea7126241c130274cd06ac4f15cbd3ec5313737a425f
```

Alternatively, the settings could be passed in a configuration file. There are
two options:

1. The `ppcli.yaml` should be located in `$HOME/.config/ppcli` or current directory
2. Pass the location via `-config` flag

```yaml
---
service_principal: 8c5e8866-0062-4059-b2be-92707e4374da
principal_secret: f982025ecbaa8c42bec8b19c98c3ea7126241c130274cd06ac4f15cbd3ec5313737a425f
```

The following command fetches all events occured in the last 60 minutes
from Proofpoint SIEM API:

```bash
ppcli -service-name siem -service-operation all -log-level debug
```

## References

* [Threat Insight Dashboard - API Documentation](https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation)
