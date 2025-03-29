# End to End Encrypted File Sharing

Ever wished that your files were actually safe when you upload them? This application
aims to do exactly that! It uses [RustCrypto](https://github.com/RustCrypto) to encrypt
your files before uploading them to our servers, ensuring that your files cannot be
read by anyone except those that you share them with.

The application is currently still under development. It is divided into four main
components:

- [Corelib](#corelib)
- [Server](#server)
- [CLI](#cli)
- [Client](#client)

## Corelib

The corelib contains the core logic of the application. It is responsible for
generating keys, encrypting and decrypting files, and storing them on disk
securely.

The corelib is a library and not a standalone application. So, it cannot be executed
and can only be tested:

```bash
cargo test
```

## Server

The server is the main component of the application. It is responsible for handling
user authentication, file uploads, and file downloads.

The server is a standalone application and can be executed:

```bash
cargo run
```

## CLI

The CLI is a command line interface for the application. It is one of the
user-facing components of the application.

It is a standalone application and can be executed, although the server must be
running, and the proper command line arguments must be provided.

```bash
cargo run -- --help
```

## Client

The client is the other user-facing component of the application. It does the same
thing as the CLI, but with a GUI. It is written using [Tauri](https://tauri.app/).

Since Tauri requires both Rust and Node.js, run the following command to get started
with both:

```bash
pnpm install
pnpm tauri dev
```

> Note: `pnpm` can be replaced with `yarn`, `npm`, or your preferred package manager.
