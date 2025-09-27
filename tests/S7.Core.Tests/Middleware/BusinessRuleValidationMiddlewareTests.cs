using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Commands;
using S7.Services.Middleware;
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace S7.Core.Tests.Middleware
{
    /// <summary>
    /// Unit tests for BusinessRuleValidationMiddleware class.
    /// </summary>
    public class BusinessRuleValidationMiddlewareTests : IDisposable
    {
        private readonly Mock<ILogger<BusinessRuleValidationMiddleware<MemoryDumpOptions>>> _mockLogger;
        private readonly BusinessRuleValidationMiddleware<MemoryDumpOptions> _middleware;
        private readonly string _tempDirectory;
        private readonly string _tempFile;

        public BusinessRuleValidationMiddlewareTests()
        {
            _mockLogger = new Mock<ILogger<BusinessRuleValidationMiddleware<MemoryDumpOptions>>>();
            _middleware = new BusinessRuleValidationMiddleware<MemoryDumpOptions>(_mockLogger.Object);
            
            // Create temporary directory and file for testing
            _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
            _tempFile = Path.Combine(_tempDirectory, "test.bin");
            File.WriteAllText(_tempFile, "test content");
        }

        public void Dispose()
        {
            // Clean up temporary files
            if (Directory.Exists(_tempDirectory))
            {
                Directory.Delete(_tempDirectory, true);
            }
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new BusinessRuleValidationMiddleware<MemoryDumpOptions>(null!));
        }

        [Fact]
        public void Order_ReturnsCorrectValue()
        {
            // Assert
            Assert.Equal(20, _middleware.Order);
        }

        [Fact]
        public void StopOnFailure_ReturnsTrue()
        {
            // Assert
            Assert.True(_middleware.StopOnFailure);
        }

        [Fact]
        public async Task ValidateAsync_WithNullOptions_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _middleware.ValidateAsync(null!, CancellationToken.None));
        }

        [Fact]
        public async Task ValidateAsync_WithValidMemoryDumpOptions_ReturnsSuccess()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                StartAddress = 0x1000, // 4-byte aligned
                Length = 1024, // 4-byte aligned
                OutputPath = _tempFile,
                ChunkSize = 512
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateAsync_WithInvalidCorrelationId_ReturnsFailure()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "", // Invalid - empty
                TimeoutMs = 30000,
                StartAddress = 0x1000,
                Length = 1024
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("CorrelationId cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithInvalidTimeout_ReturnsFailure()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 0, // Invalid - must be > 0
                StartAddress = 0x1000,
                Length = 1024
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("TimeoutMs must be greater than 0", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithExcessiveTimeout_ReturnsFailure()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 4000000, // Invalid - exceeds 1 hour
                StartAddress = 0x1000,
                Length = 1024
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("TimeoutMs cannot exceed 1 hour", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithUnalignedStartAddress_ReturnsFailure()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                StartAddress = 0x1001, // Not 4-byte aligned
                Length = 1024
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("StartAddress must be 4-byte aligned", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithUnalignedLength_ReturnsFailure()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                StartAddress = 0x1000,
                Length = 1023 // Not 4-byte aligned
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Length should be 4-byte aligned", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithInvalidChunkSize_ReturnsFailure()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                StartAddress = 0x1000,
                Length = 1024,
                ChunkSize = 2048 // Larger than total length
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("ChunkSize cannot be larger than total Length", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithNonExistentOutputDirectory_ReturnsFailure()
        {
            // Arrange
            var nonExistentPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString(), "output.bin");
            var options = new MemoryDumpOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                StartAddress = 0x1000,
                Length = 1024,
                OutputPath = nonExistentPath
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Output directory does not exist", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithValidStagerInstallOptions_ReturnsSuccess()
        {
            // Arrange
            var stagerMiddleware = new BusinessRuleValidationMiddleware<StagerInstallOptions>(
                new Mock<ILogger<BusinessRuleValidationMiddleware<StagerInstallOptions>>>().Object);

            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x2000,
                MaxPayloadSize = 1024 * 1024,
                BackupBeforeInstall = false
            };

            // Act
            var result = await stagerMiddleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateAsync_WithNonExistentPayloadFile_ReturnsFailure()
        {
            // Arrange
            var stagerMiddleware = new BusinessRuleValidationMiddleware<StagerInstallOptions>(
                new Mock<ILogger<BusinessRuleValidationMiddleware<StagerInstallOptions>>>().Object);

            var nonExistentFile = Path.Combine(_tempDirectory, "nonexistent.bin");
            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = nonExistentFile,
                TargetAddress = 0x2000
            };

            // Act
            var result = await stagerMiddleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload file does not exist", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithLowTargetAddress_ReturnsFailure()
        {
            // Arrange
            var stagerMiddleware = new BusinessRuleValidationMiddleware<StagerInstallOptions>(
                new Mock<ILogger<BusinessRuleValidationMiddleware<StagerInstallOptions>>>().Object);

            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x500 // Below 0x1000 threshold
            };

            // Act
            var result = await stagerMiddleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("TargetAddress should be above 0x1000", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithExcessivePayloadSize_ReturnsFailure()
        {
            // Arrange
            var stagerMiddleware = new BusinessRuleValidationMiddleware<StagerInstallOptions>(
                new Mock<ILogger<BusinessRuleValidationMiddleware<StagerInstallOptions>>>().Object);

            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x2000,
                MaxPayloadSize = 5 // Smaller than actual file size
            };

            // Act
            var result = await stagerMiddleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload file size", result.Error.Message);
            Assert.Contains("exceeds MaxPayloadSize", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithBackupEnabledButNoPath_ReturnsFailure()
        {
            // Arrange
            var stagerMiddleware = new BusinessRuleValidationMiddleware<StagerInstallOptions>(
                new Mock<ILogger<BusinessRuleValidationMiddleware<StagerInstallOptions>>>().Object);

            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x2000,
                BackupBeforeInstall = true,
                BackupFilePath = null // Missing backup path
            };

            // Act
            var result = await stagerMiddleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("BackupFilePath is required when BackupBeforeInstall is enabled", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithPowerCycleEnabledButNoDelay_ReturnsFailure()
        {
            // Arrange
            var stagerMiddleware = new BusinessRuleValidationMiddleware<StagerInstallOptions>(
                new Mock<ILogger<BusinessRuleValidationMiddleware<StagerInstallOptions>>>().Object);

            var options = new StagerInstallOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                PayloadPath = _tempFile,
                TargetAddress = 0x2000,
                PowerCycleBeforeInstall = true,
                PowerCycleDelayMs = 0 // Invalid delay
            };

            // Act
            var result = await stagerMiddleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("PowerCycleDelayMs must be greater than 0", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithMultipleBusinessRuleViolations_ReturnsAggregatedErrors()
        {
            // Arrange
            var options = new MemoryDumpOptions
            {
                CorrelationId = "", // Invalid
                TimeoutMs = 0, // Invalid
                StartAddress = 0x1001, // Unaligned
                Length = 1023 // Unaligned
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("CorrelationId cannot be null or empty", result.Error.Message);
            Assert.Contains("TimeoutMs must be greater than 0", result.Error.Message);
            Assert.Contains("StartAddress must be 4-byte aligned", result.Error.Message);
            Assert.Contains("Length should be 4-byte aligned", result.Error.Message);
        }
    }
}