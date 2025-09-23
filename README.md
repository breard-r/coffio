# Coffio

[![Build Status](https://github.com/breard-r/coffio/actions/workflows/ci.yml/badge.svg)](https://github.com/breard-r/coffio/actions/workflows/ci.yml)
[![Coffio on crates.io](https://img.shields.io/crates/v/coffio.svg)](https://crates.io/crates/coffio)
[![Coffio on docs.rs](https://docs.rs/coffio/badge.svg)](https://docs.rs/coffio/)
![License MIT OR Apache 2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

Abstraction layer for symmetric data encryption, primarily designed for
database column encryption.


# Disclaimer

⚠️ DANGER: DRAGONS A(H)EAD! 🐲

This crate is experimental and has never been audited by an independent
security professional. You should therefore NOT use it in production.

Although this crate aim to reduce the risk of misuse, it is still possible to
use it in such a way that the cryptography it uses does not provides all the
security guaranties you need. Ask your cryptographer if this crate is relevant
to your use case and if you are using it correctly.


# Frequently Asked Questions

## Should I use this crate?

If you have a use case covered by this crate AND you do not mind about using an
experimental crate, then you may use it.

## Why should I use this crate instead of a symmetric encryption function?

1. Strong algorithms only. If you don't know which one to chose, Coffio
   provides strong defaults.
2. Key management is hard. Coffio largely simplifies it in a way that becomes
   largely accessible.

## Why has this crate not been audited by a security professional?

Such an audit cost a lot of money. If you really care about this crate being
audited, you may help financing it.

## Where does the name coffio comes from?

It is a french slang for a safe or a strongbox. See
[coffio](https://fr.wiktionary.org/wiki/coffio) on the french Wiktionary.
