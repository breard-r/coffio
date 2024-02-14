
[//]: # (Copyright 2019-2020 Rodolphe Bréard <rodolphe@breard.tf>)

[//]: # (Copying and distribution of this file, with or without modification,)
[//]: # (are permitted in any medium without royalty provided the copyright)
[//]: # (notice and this notice are preserved.  This file is offered as-is,)
[//]: # (without any warranty.)


# Coffio

![License MIT OR Apache 2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)

Abstraction layer for symmetric data encryption, primarily designed for database column encryption.


# Disclaimer

:warning: DANGER: DRAGONS A(H)EAD! :dragon_face:

This crate is experimental and has never been audited by an independent security professional. You should therefore NOT use it in production.

Although this crate aim to reduce the risk of misuse, it is still possible to use it in such a way that the cryptography it uses does not provides all the security guaranties you need. Ask your cryptographer if this crate is relevant to your use case and if you are using it correctly.


# Frequently Asked Questions

## Should I use this project?

Not yet.

## Why shouldn't I directly use a symmetric encryption function instead of this crate?

Cryptography is hard and, even if you some knowledge about it and pay attention, you may misuse it.

## Why is the context so important?

It helps preventing a confused deputy attack.

## Where does the name coffio comes from?

It is a french slang for a safe or a strongbox. See [coffio](https://fr.wiktionary.org/wiki/coffio) on the french Wiktionary.
