# RadixDLT Olympia Network Gateway

> [!CAUTION]
> This is **Olympia** network compatible network gateway. RadixDLT currently runs babylon compatible network and this network gateway is **NOT** compatible with it.
> 
> Network Gateway compatible with current network is available here https://github.com/radixdlt/babylon-gateway

#
This system is designed to be the Radix-run publicly exposed gateway into the Olympia Radix network, and replaces the archive module which previously ran on-node.

The system is in two main parts:
* **Data Aggregator** - Reads from the Core API of one or more full nodes, ingesting from their Transaction API and Mempool Contents API, and committing transactions to a PostgreSQL database. It also handles the pruning (and resubmission where relevant) of submitted transactions. This project has ownership of the schema migrations.
* **Gateway API** - Provides the public API for Wallets and Explorers, and maps construction and submission requests to the Core API of one or more full nodes.

## Using the Gateway API

For documentation on the Gateway API, see the [Gateway API docs on ReDocly](https://redocly.github.io/redoc/?url=https://raw.githubusercontent.com/radixdlt/radixdlt-network-gateway/main/gateway-api-spec.yaml).

## Technical Docs

For docs giving an overview of the Network Gateway and its place in the Radix Ecosystem - including information on the Radix-run Network Gateway, and how to run one of your own - check out [the Radix docs site](https://docs.radixdlt.com/).

For docs related to development on the Network Gateway, see the [docs folder](./docs).

For docs related to running a Network Gateway locally, see the instructions about running a local toy deployment in the [deployment folder](./deployment).
