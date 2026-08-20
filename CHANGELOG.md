# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.2](https://github.com/SecurityRonin/state-history-forensic/compare/state-history-forensic-v0.2.1...state-history-forensic-v0.2.2) - 2026-08-20

### Fixed

- *(gitignore)* unanchor the target rule so nested cargo projects are ignored

## [0.2.1](https://github.com/SecurityRonin/state-history-forensic/compare/state-history-forensic-v0.2.0...state-history-forensic-v0.2.1) - 2026-08-05

### Fixed

- *(supply-chain)* trust our own crates instead of exempting them

## [0.2.0](https://github.com/SecurityRonin/state-history-forensic/compare/state-history-forensic-v0.1.0...state-history-forensic-v0.2.0) - 2026-08-04

### Added

- *(identity)* [P] persistent evidential address (canonical binary key)

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)
- use verbatim Apache-2.0 license text

### Fixed

- *(fmt,vet)* the fallout of the edition and lockfile change
- *(msrv)* edition 2021 and a 1.75 floor — the 2024 edition was never used
