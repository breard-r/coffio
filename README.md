
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

## Should I use this crate?

No, absolutely not. It doesn't even work yet.

## Why should I use this crate instead of a symmetric encryption function?

Cryptography is hard. Even if you have some knowledge about this topic and pay attention not no mess up, you will eventually mess-up anyway.

Seriously, this crate is designed to prevent some of the most common pitfalls. If you don't see why you need this crate, you probably don't see those pitfalls and you will fall into it.

## Why is the context so important?

When correctly used, it prevents from a confused deputy attack. Chose wisely.

## Why has this crate not been audited by a security professional?

Such an audit cost a lot of money. If you really care about this crate being audited, you may help financing it.

## Where does the name coffio comes from?

It is a french slang for a safe or a strongbox. See [coffio](https://fr.wiktionary.org/wiki/coffio) on the french Wiktionary.
