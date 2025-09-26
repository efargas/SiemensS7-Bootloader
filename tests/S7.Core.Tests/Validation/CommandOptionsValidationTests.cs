using S7.Core.Abstractions.Commands;
using System;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using Xunit;

namespace S7.Core.Tests.Validation
{
    /// <summary>
    /// Unit tests for command options validation functionality.
    /// </summary>
    public class CommandOptionsValidationTests : IDisposable
    {
        private readonly string _tempDirectory;
        private readonly string _tempFile;

        public CommandOptionsValidationTests()
        {
            // Create temporary directory and file for testing
            _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            _tempFile = Path.Combine(_tempDirectory, "test.bin");
            File.WriteAllText(_tempFile, "test content for payload");
        }

        public void Dispose()
        {
            // Clean up temporary files
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }

        #region MemoryDumpOptions Validation Tests

        [Fact]
        public void MemoryDumpOptions_WithValidProperties_PassesValidation()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Address = 0x20000000,
                Length = 1024,
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory,
                ChunkSize = 256
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.Empty(validationResults);
        }

        [Fact]
        public void MemoryDumpOptions_WithInvalidAddress_FailsValidation()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Address = 0x100000000, // Exceeds 32-bit range
                Length = 1024,
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("Address"));
        }

        [Fact]
        public void MemoryDumpOptions_WithInvalidLength_FailsValidation()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Address = 0x20000000,
                Length = 0, // Invalid length
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("Length"));
        }

        [Fact]
        public void MemoryDumpOptions_WithInvalidPayloadPath_FailsValidation()
        {
            // Arrange
            var nonExistentFile = Path.Combine(_tempDirectory, "nonexistent.bin");
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Address = 0x20000000,
                Length = 1024,
                PayloadPath = nonExistentFile, // Non-existent file
                OutputPath = _tempDirectory
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("PayloadPath"));
        }

        [Fact]
        public void MemoryDumpOptions_WithInvalidOutputPath_FailsValidation()
        {
            // Arrange
            var nonExistentDirectory = Path.Combine(_tempDirectory, "nonexistent");
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Address = 0x20000000,
                Length = 1024,
                PayloadPath = _tempFile,
                OutputPath = nonExistentDirectory // Non-existent directory
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("OutputPath"));
        }

        [Fact]
        public void MemoryDumpOptions_WithInvalidTimeout_FailsValidation()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 1000, // Below minimum (5 seconds)
                Address = 0x20000000,
                Length = 1024,
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("TimeoutMs"));
        }

        [Fact]
        public void MemoryDumpOptions_WithInvalidChunkSize_FailsValidation()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Address = 0x20000000,
                Length = 1024,
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory,
                ChunkSize = 1025 // Not 4-byte aligned
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("ChunkSize"));
        }

        [Fact]
        public void MemoryDumpOptions_CustomValidation_ValidatesBusinessRules()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Address = 0x20000000,
                Length = 1024,
                PayloadPath = _tempFile,
                OutputPath = _tempDirectory,
                ChunkSize = 2048 // Larger than total length
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("ChunkSize cannot be larger than Length"));
        }

        #endregion

        #region StagerInstallOptions Validation Tests

        [Fact]
        public void StagerInstallOptions_WithValidProperties_PassesValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x20000000,
                MaxPayloadSize = 1024 * 1024,
                CreateBackup = false,
                PowerCycleBeforeInstall = false
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.Empty(validationResults);
        }

        [Fact]
        public void StagerInstallOptions_WithInvalidPayloadPath_FailsValidation()
        {
            // Arrange
            var nonExistentFile = Path.Combine(_tempDirectory, "nonexistent.bin");
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = nonExistentFile, // Non-existent file
                TargetAddress = 0x20000000,
                MaxPayloadSize = 1024 * 1024
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("PayloadPath"));
        }

        [Fact]
        public void StagerInstallOptions_WithInvalidTargetAddress_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x500, // Below minimum (0x1000)
                MaxPayloadSize = 1024 * 1024
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("TargetAddress"));
        }

        [Fact]
        public void StagerInstallOptions_WithInvalidMaxPayloadSize_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x20000000,
                MaxPayloadSize = 1023 // Not 1KB aligned
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("MaxPayloadSize"));
        }

        [Fact]
        public void StagerInstallOptions_WithInvalidTimeout_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 5000, // Below minimum (10 seconds)
                PayloadPath = _tempFile,
                TargetAddress = 0x20000000,
                MaxPayloadSize = 1024 * 1024
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("TimeoutMs"));
        }

        [Fact]
        public void StagerInstallOptions_WithBackupEnabledButNoPath_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x20000000,
                MaxPayloadSize = 1024 * 1024,
                CreateBackup = true,
                BackupFilePath = null // Missing backup path
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("BackupFilePath is required when CreateBackup is enabled"));
        }

        [Fact]
        public void StagerInstallOptions_WithPowerCycleEnabledButNoDelay_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x20000000,
                MaxPayloadSize = 1024 * 1024,
                PowerCycleBeforeInstall = true,
                PowerCycleDelayMs = 0 // Invalid delay
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("PowerCycleDelayMs must be greater than 0"));
        }

        [Fact]
        public void StagerInstallOptions_WithExcessivePayloadSize_FailsValidation()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x20000000,
                MaxPayloadSize = 10 // Smaller than actual file size
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("Payload file size exceeds MaxPayloadSize"));
        }

        #endregion

        #region CommandHandlerOptions Base Class Tests

        [Fact]
        public void CommandHandlerOptions_WithValidBaseProperties_PassesValidation()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                Priority = CommandPriority.Normal,
                EnableDetailedLogging = true
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.Empty(validationResults);
        }

        [Fact]
        public void CommandHandlerOptions_WithInvalidCorrelationId_FailsValidation()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "", // Empty correlation ID
                TimeoutMs = 30000
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("CorrelationId"));
        }

        [Fact]
        public void CommandHandlerOptions_WithInvalidTimeoutMs_FailsValidation()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 0 // Invalid timeout
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("TimeoutMs"));
        }

        [Fact]
        public void CommandHandlerOptions_WithRetryPolicy_ValidatesRetrySettings()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RetryPolicy = new RetryPolicy
                {
                    MaxRetries = -1, // Invalid
                    RetryDelayMs = 1000
                }
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.NotEmpty(validationResults);
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("MaxRetries"));
        }

        [Fact]
        public void CommandHandlerOptions_WithValidRetryPolicy_PassesValidation()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RetryPolicy = new RetryPolicy
                {
                    MaxRetries = 3,
                    RetryDelayMs = 1000,
                    UseExponentialBackoff = true,
                    RetryableExceptions = new[] { typeof(TimeoutException) }
                }
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.Empty(validationResults);
        }

        #endregion

        #region Multiple Validation Errors Tests

        [Fact]
        public void MemoryDumpOptions_WithMultipleInvalidProperties_ReturnsAllErrors()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "", // Invalid
                TimeoutMs = 1000, // Invalid (too low)
                Address = 0x100000000, // Invalid (exceeds 32-bit)
                Length = 0, // Invalid
                PayloadPath = "nonexistent.bin", // Invalid
                ChunkSize = 1025 // Invalid (not aligned)
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.True(validationResults.Count >= 5); // Should have multiple errors
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("CorrelationId"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("TimeoutMs"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("Address"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("Length"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("PayloadPath"));
        }

        [Fact]
        public void StagerInstallOptions_WithMultipleInvalidProperties_ReturnsAllErrors()
        {
            // Arrange
            var options = new StagerInstallOptions
            {
                CorrelationId = "", // Invalid
                TimeoutMs = 5000, // Invalid (too low)
                PayloadPath = "nonexistent.bin", // Invalid
                TargetAddress = 0x500, // Invalid (too low)
                MaxPayloadSize = 1023, // Invalid (not aligned)
                CreateBackup = true,
                BackupFilePath = null, // Invalid (missing when backup enabled)
                PowerCycleBeforeInstall = true,
                PowerCycleDelayMs = 0 // Invalid (zero delay)
            };

            // Act
            var validationResults = options.Validate();

            // Assert
            Assert.True(validationResults.Count >= 6); // Should have multiple errors
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("CorrelationId"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("TimeoutMs"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("PayloadPath"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("TargetAddress"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("MaxPayloadSize"));
            Assert.Contains(validationResults, vr => vr.ErrorMessage.Contains("BackupFilePath"));
        }

        #endregion

        #region Test Helper Classes

        /// <summary>
        /// Test command options class for testing base class validation.
        /// </summary>
        private class TestCommandOptions : CommandHandlerOptions
        {
            public TestCommandOptions()
            {
                CorrelationId = Guid.NewGuid().ToString();
                TimeoutMs = 30000;
            }
        }

        #endregion
    }
}