# API Specifications

There are (at time of writing) three main Radix APIs:

* [Gateway API](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/radixdlt/radixdlt-network-gateway/main/gateway-api-spec.yaml) - The main public facing API, exposed by the Network Gateway
* [Core API](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/radixdlt/radixdlt/main/radixdlt-core/radixdlt/src/main/java/com/radixdlt/api/core/api.yaml) - An API exposed by radixdlt full nodes, intended to be exposed on private networks
* [System API](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/radixdlt/radixdlt/main/radixdlt-core/radixdlt/src/main/java/com/radixdlt/api/system/api.yaml) - An API exposed privately by radixdlt nodes to get information about the node health/status.

The links above link to the ReDocly docs, reading the schemas on the `main` branches of each repo. As such, they may include features that are not yet on the latest release.

## Gateway API

As the Gateway API is exposed by the Gateway Service, the Gateway API specification source-of-truth lives in the [Open API Spec in the Network Gateway repository](../gateway-api-spec.yaml).

The Open API specification should be kept up to date with the interface that the Gateway API service exposes.

## Core and System APIs

The source of truth for the Core and System APIs lives on the full node - and the specs on the `main` branch are here: [Core Open API Spec](https://github.com/radixdlt/radixdlt/blob/main/radixdlt-core/radixdlt/src/main/java/com/radixdlt/api/core/api.yaml) | [System Open API Spec](https://github.com/radixdlt/radixdlt/blob/main/radixdlt-core/radixdlt/src/main/java/com/radixdlt/api/system/api.yaml).

## Model and Client Generation

The Gateway Service uses the `openapi-generator` to generate models and clients against the Gateway API spec and the Core API spec. More information can be found in the [generation folder README](../generation).
