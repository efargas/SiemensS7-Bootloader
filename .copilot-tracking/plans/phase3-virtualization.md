# Phase 3 — Virtualization and PageCache

## Goals
- IVirtualFileReader interface and Page DTO
- MemoryMappedFile and FileStream readers plus factory
- PageCache with dedupe, throttle, and LRU eviction
- HexViewer wiring and integration tests
- CI tests and sample synthetic-file demo

## Tasks
- [ ] Create IVirtualFileReader and Page DTO in S7.Core
- [ ] Implement MemoryMappedFileVirtualReader in S7.Services
- [ ] Implement FileStream fallback reader in S7.Services
- [ ] Implement PageCache in S7.Infrastructure with dedupe/throttle/LRU
- [ ] Add unit tests for dedupe/cancel/throttle
- [ ] Wire HexViewerViewModel to IVirtualFileReader and placeholders
- [ ] Integration demo with synthetic file and QA report

## Acceptance
- Unit tests pass locally and in CI
- Demo app shows smooth scrolling on synthetic large file
- Cancellation and dedupe tests green

