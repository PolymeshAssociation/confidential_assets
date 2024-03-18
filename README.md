[![Discord](https://img.shields.io/badge/Discord-Join_our_server-blue.svg?style=social&logo=discord)](https://discord.com/invite/ud2deWAnyt) 
![Twitter Follow](https://img.shields.io/twitter/follow/PolymeshNetwork?style=social)

<img src="Polymesh-logo.svg" width="70%" alt="Polymesh"/>

# Polymesh Private

Polymesh Private is intended to be a private instance of the Polymesh blockchain, run within a private network.

Polymesh Private also includes some additional functionality to allow for the creation, management and settlement of confidential assets, using encrypted balances and zero-knowledge proofs with on-chain verification.

For information on Polymesh, please see:
<https://github.com/PolymeshAssociation/Polymesh>

# Networks

Polymesh Private has two runtimes configured - production and development. These are largely similar except that the development runtime includes the "sudo" pallet.

# Documentation

Further details on Polymesh concepts and networks can be found at:

<https://developers.polymesh.network/>

Code documentation can be found at:

<https://docs.polymesh.live/>

# Build

To prepare your development environment with the required compiler and tools refer to https://docs.substrate.io/main-docs/install/ for instructions applicable to your operating system.

Build Wasm and native code:

```bash
cargo build --release
```

# Development

## Single node development chain

You can start a development chain with:

```bash
./target/release/polymesh-private --dev
```

Detailed logs may be shown by running the node with the following environment variables set:
`RUST_LOG=debug RUST_BACKTRACE=1 ./target/release/polymesh-private --dev`.

[Web Interface]: https://mainnet-app.polymesh.network/#/explorer

To access the Polymesh Chain using the [Web Interface] do the following:

1. Click on the Polymesh logo in the top-left corner of the UI. You can then select "Local Node" under the Development section.

   > Note: if the `polymesh-private` node above is on a different machine than your browser (e.g., a server on your local network), you'll need to use a *"custom endpoint"*, e.g., `ws://192.168.0.100:9944/`.
   > The [Web Interface] uses `https`, but your `polymesh-private` instance does not, so you'll need `ws://` as opposed to `wss://`. You'll also need to use `http://httpapp.polymesh.live/` instead of [Web Interface]. Otherwise, you'll have problems with mixed-content blocking (https vs. http).
   > Finally, add `--rpc-external --ws-external --rpc-cors all` to the `polymesh-private` invocation above.

3. Reload the page.

# License

[LICENSE](https://github.com/PolymeshAssociation/Polymesh-private/blob/main/LICENSE.pdf)

Use of the software is governed by the license in, LICENSE.pdf. Commercial licenses are available, for inquires relating to commercial licenses please contact info@polymesh.network.

# Substrate Framework

Polymesh is built using the [Substrate Framework](https://www.parity.io/what-is-substrate/).

# Polymesh Website

[Polymesh Website](https://polymesh.network)
