# Phase3 Task: IVirtualFileReader and Page DTO details

Goal
- Add IVirtualFileReader and Page DTO to S7.Core.

Requirements
- IVirtualFileReader:
  - Task<Page> ReadPageAsync(long pageIndex, int pageSize, CancellationToken ct)
  - long Length { get; }
  - int PageSize { get; }
- Page DTO:
  - record Page(long PageIndex, ReadOnlyMemory<byte> Data, int Length)

Tests
- Contract tests: null params handling and cancellation propagation.

Notes
- Keep types immutable and allocation-light.
