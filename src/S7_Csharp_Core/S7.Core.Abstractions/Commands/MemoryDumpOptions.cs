using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using S7.Core.Abstractions.Configuration;
using S7.Core.Abstractions.Validation;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Options for memory dump command handler operations.
    /// </summary>
    public class MemoryDumpOptions : CommandHandlerOptions
    {
        /// <summary>
        /// Gets or sets the starting memory address for the dump operation.
        /// </summary>
        [Required(ErrorMessage = "Memory address is required")]
        [NumericRange(0, uint.MaxValue, ErrorMessage = "Address must be a valid 32-bit unsigned integer")]
        public uint Address { get; set; }

        /// <summary>
        /// Gets or sets the starting memory address for the dump operation (alias for Address).
        /// </summary>
        public uint StartAddress 
        { 
            get => Address; 
            set => Address = value; 
        }

        /// <summary>
        /// Gets or sets the length of memory to dump in bytes.
        /// </summary>
        [Required(ErrorMessage = "Memory length is required")]
        [NumericRange(1, uint.MaxValue, Alignment = 4, ErrorMessage = "Length must be at least 1 byte and aligned to 4-byte boundary")]
        public uint Length { get; set; }

        /// <summary>
        /// Gets or sets the path to the payload file to use for the operation.
        /// </summary>
        [Required(ErrorMessage = "Payload path is required")]
        [FilePath(AllowedExtensions = new[] { "bin", "hex", "elf" }, ErrorMessage = "Payload file must exist and have a valid extension (.bin, .hex, .elf)")]
        public string PayloadPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the output directory path where the dump file will be saved.
        /// </summary>
        [Required(ErrorMessage = "Output path is required")]
        [FilePath(MustExist = false, AllowDirectories = true, AllowEmpty = false, ErrorMessage = "Output path must be a valid directory path")]
        public string OutputPath { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the communication channel configuration.
        /// </summary>
        [Required(ErrorMessage = "Channel configuration is required")]
        public CommunicationChannelConfig ChannelConfig { get; set; } = new();

        /// <summary>
        /// Gets or sets a value indicating whether to overwrite existing dump files.
        /// </summary>
        public bool OverwriteExisting { get; set; } = false;

        /// <summary>
        /// Gets or sets the custom filename for the dump file (optional).
        /// If not specified, a default filename will be generated.
        /// </summary>
        [StringLength(255, ErrorMessage = "Custom filename cannot exceed 255 characters")]
        [RegularExpression(@"^[^<>:""/\\|?*]+$", ErrorMessage = "Custom filename contains invalid characters")]
        public string? CustomFilename { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to perform a handshake before the dump operation.
        /// </summary>
        public bool PerformHandshake { get; set; } = true;

        /// <summary>
        /// Gets or sets the timeout for the entire dump operation in milliseconds.
        /// Overrides the base TimeoutMs property with dump-specific default.
        /// </summary>
        [Timeout(MinTimeoutMs = 5000, MaxTimeoutMs = 3600000, ErrorMessage = "Operation timeout must be between 5 seconds and 1 hour")]
        public new int TimeoutMs { get; set; } = 600000; // 10 minutes default for memory dumps

        /// <summary>
        /// Gets or sets the chunk size for reading memory in bytes.
        /// Larger chunks may be faster but use more memory.
        /// </summary>
        [NumericRange(1, 65536, Alignment = 4, ErrorMessage = "Chunk size must be between 1 and 65536 bytes and aligned to 4-byte boundary")]
        public uint ChunkSize { get; set; } = 1024;

        /// <summary>
        /// Gets or sets a value indicating whether to verify the dump after completion.
        /// </summary>
        public bool VerifyDump { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether to validate checksums during the dump operation.
        /// </summary>
        public bool ValidateChecksum { get; set; } = true;

        /// <summary>
        /// Gets or sets the maximum number of retry attempts for failed read operations.
        /// </summary>
        [Range(0, 10, ErrorMessage = "Max read retries must be between 0 and 10")]
        public int MaxReadRetries { get; set; } = 3;

        /// <summary>
        /// Gets or sets the delay between read retry attempts in milliseconds.
        /// </summary>
        [Range(100, 10000, ErrorMessage = "Read retry delay must be between 100 and 10000 milliseconds")]
        public int ReadRetryDelayMs { get; set; } = 1000;

        /// <summary>
        /// Gets or sets a value indicating whether to compress the output dump file.
        /// </summary>
        public bool CompressOutput { get; set; } = false;

        /// <summary>
        /// Gets or sets the compression level (0-9) when compression is enabled.
        /// </summary>
        [Range(0, 9, ErrorMessage = "Compression level must be between 0 and 9")]
        public int CompressionLevel { get; set; } = 6;

        /// <summary>
        /// Gets or sets a value indicating whether to include performance metrics in the result.
        /// </summary>
        public bool IncludePerformanceMetrics { get; set; } = true;

        /// <summary>
        /// Gets or sets the progress reporting interval in bytes.
        /// Progress will be reported every time this many bytes have been processed.
        /// </summary>
        [Range(1024, int.MaxValue, ErrorMessage = "Progress interval must be at least 1024 bytes")]
        public int ProgressReportingInterval { get; set; } = 10240; // 10KB

        /// <summary>
        /// Validates the memory dump options and returns validation results.
        /// </summary>
        /// <returns>A collection of validation results</returns>
        public override System.Collections.Generic.IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate()
        {
            var results = base.Validate().ToList();

            // Validate address + length doesn't overflow
            if (Address > uint.MaxValue - Length)
            {
                results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                    "Address + Length would cause integer overflow",
                    new[] { nameof(Address), nameof(Length) }));
            }

            // Validate output file doesn't exist if overwrite is disabled
            if (!OverwriteExisting && !string.IsNullOrEmpty(CustomFilename))
            {
                var outputPath = Path.Combine(OutputPath, CustomFilename);
                if (File.Exists(outputPath))
                {
                    results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                        $"Output file already exists and overwrite is disabled: {outputPath}",
                        new[] { nameof(CustomFilename), nameof(OverwriteExisting) }));
                }
            }

            // Validate chunk size is reasonable for the total length
            if (ChunkSize > Length)
            {
                results.Add(new System.ComponentModel.DataAnnotations.ValidationResult(
                    "Chunk size cannot be larger than total length",
                    new[] { nameof(ChunkSize), nameof(Length) }));
            }

            return results;
        }
    }
}