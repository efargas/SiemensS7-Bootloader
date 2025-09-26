using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Net;
using S7.Services;
using S7.Utils;
using Xunit;

namespace S7_Csharp_Utility.Tests.Services
{
    /// <summary>
    /// Unit tests for PayloadService to verify payload management functionality and error handling.
    /// </summary>
    public class PayloadServiceTests : IDisposable
    {
        private readonly Mock<ILogger<PayloadService>> _mockLogger;
        private readonly Mock<PayloadManager> _mockPayloadManager;
        private readonly PayloadService _service;
        private readonly string _tempDirectory;

        public PayloadServiceTests()
        {
            _mockLogger = new Mock<ILogger<PayloadService>>();
            _mockPayloadManager = new Mock<PayloadManager>(AppContext.BaseDirectory);
            _service = new PayloadService(_mockLogger.Object, _mockPayloadManager.Object);
            _tempDirectory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Directory.CreateDirectory(_tempDirectory);
        }

        public void Dispose()
        {
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
                new PayloadService(null!, _mockPayloadManager.Object));
        }

        [Fact]
        public void Constructor_WithNullPayloadManager_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new PayloadService(_mockLogger.Object, null!));
        }

        [Fact]
        public async Task ScanPayloadsAsync_WithValidDirectory_ReturnsPayloads()
        {
            // Arrange
            var payloadDirectory = _tempDirectory;
            CreateTestPayloadFiles();

            var mockProgress = new Mock<IProgress<PayloadScanProgress>>();
            var expectedPayloads = new[]
            {
                new PayloadInfo { Name = "test1.bin", Path = Path.Combine(payloadDirectory, "test1.bin"), Size = 100 },
                new PayloadInfo { Name = "test2.hex", Path = Path.Combine(payloadDirectory, "test2.hex"), Size = 200 }
            };

            _mockPayloadManager
                .Setup(x => x.ScanPayloadsAsync(It.IsAny<string>(), It.IsAny<IProgress<PayloadScanProgress>>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(expectedPayloads);

            // Act
            var result = await _service.ScanPayloadsAsync(payloadDirectory, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Equal(2, result.Value.Count());
        }

        [Fact]
        public async Task ScanPayloadsAsync_WithNullDirectory_ReturnsFailure()
        {
            // Arrange
            string payloadDirectory = null!;
            var mockProgress = new Mock<IProgress<PayloadScanProgress>>();

            // Act
            var result = await _service.ScanPayloadsAsync(payloadDirectory, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Directory path cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task ScanPayloadsAsync_WithNonExistentDirectory_ReturnsFailure()
        {
            // Arrange
            var payloadDirectory = Path.Combine(_tempDirectory, "nonexistent");
            var mockProgress = new Mock<IProgress<PayloadScanProgress>>();

            // Act
            var result = await _service.ScanPayloadsAsync(payloadDirectory, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Directory does not exist", result.Error.Message);
        }

        [Fact]
        public async Task ScanPayloadsAsync_WithCancellation_ThrowsOperationCanceledException()
        {
            // Arrange
            var payloadDirectory = _tempDirectory;
            var mockProgress = new Mock<IProgress<PayloadScanProgress>>();
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _service.ScanPayloadsAsync(payloadDirectory, mockProgress.Object, cancellationTokenSource.Token));
        }

        [Fact]
        public async Task LoadPayloadAsync_WithValidPath_ReturnsPayload()
        {
            // Arrange
            var payloadPath = Path.Combine(_tempDirectory, "test.bin");
            var testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            await File.WriteAllBytesAsync(payloadPath, testData);

            var expectedPayload = new PayloadInfo 
            { 
                Name = "test.bin", 
                Path = payloadPath, 
                Size = testData.Length,
                Data = testData
            };

            _mockPayloadManager
                .Setup(x => x.LoadPayloadAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(expectedPayload);

            // Act
            var result = await _service.LoadPayloadAsync(payloadPath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Equal("test.bin", result.Value.Name);
            Assert.Equal(testData.Length, result.Value.Size);
        }

        [Fact]
        public async Task LoadPayloadAsync_WithNullPath_ReturnsFailure()
        {
            // Arrange
            string payloadPath = null!;

            // Act
            var result = await _service.LoadPayloadAsync(payloadPath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload path cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task LoadPayloadAsync_WithNonExistentFile_ReturnsFailure()
        {
            // Arrange
            var payloadPath = Path.Combine(_tempDirectory, "nonexistent.bin");

            // Act
            var result = await _service.LoadPayloadAsync(payloadPath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload file does not exist", result.Error.Message);
        }

        [Fact]
        public async Task ValidatePayloadAsync_WithValidPayload_ReturnsSuccess()
        {
            // Arrange
            var payloadPath = Path.Combine(_tempDirectory, "test.bin");
            var testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            await File.WriteAllBytesAsync(payloadPath, testData);

            var validationResult = new PayloadValidationResult
            {
                IsValid = true,
                FileSize = testData.Length,
                Checksum = "abcd1234",
                ValidationErrors = new string[0]
            };

            _mockPayloadManager
                .Setup(x => x.ValidatePayloadAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(validationResult);

            // Act
            var result = await _service.ValidatePayloadAsync(payloadPath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value.IsValid);
            Assert.Equal(testData.Length, result.Value.FileSize);
        }

        [Fact]
        public async Task ValidatePayloadAsync_WithInvalidPayload_ReturnsValidationErrors()
        {
            // Arrange
            var payloadPath = Path.Combine(_tempDirectory, "invalid.bin");
            await File.WriteAllBytesAsync(payloadPath, new byte[0]); // Empty file

            var validationResult = new PayloadValidationResult
            {
                IsValid = false,
                FileSize = 0,
                ValidationErrors = new[] { "File is empty", "Invalid format" }
            };

            _mockPayloadManager
                .Setup(x => x.ValidatePayloadAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(validationResult);

            // Act
            var result = await _service.ValidatePayloadAsync(payloadPath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.False(result.Value.IsValid);
            Assert.NotEmpty(result.Value.ValidationErrors);
        }

        [Fact]
        public async Task CompilePayloadAsync_WithValidSource_ReturnsSuccess()
        {
            // Arrange
            var sourcePath = Path.Combine(_tempDirectory, "source.s");
            var outputPath = Path.Combine(_tempDirectory, "output.bin");
            await File.WriteAllTextAsync(sourcePath, ".text\nmov r0, #1\n");

            var compileResult = new PayloadCompileResult
            {
                Success = true,
                OutputPath = outputPath,
                CompileTime = TimeSpan.FromSeconds(1),
                Warnings = new string[0],
                Errors = new string[0]
            };

            _mockPayloadManager
                .Setup(x => x.CompilePayloadAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(compileResult);

            // Act
            var result = await _service.CompilePayloadAsync(sourcePath, outputPath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value.Success);
            Assert.Equal(outputPath, result.Value.OutputPath);
        }

        [Fact]
        public async Task CompilePayloadAsync_WithCompileErrors_ReturnsErrors()
        {
            // Arrange
            var sourcePath = Path.Combine(_tempDirectory, "source.s");
            var outputPath = Path.Combine(_tempDirectory, "output.bin");
            await File.WriteAllTextAsync(sourcePath, "invalid assembly code");

            var compileResult = new PayloadCompileResult
            {
                Success = false,
                CompileTime = TimeSpan.FromSeconds(0.5),
                Warnings = new[] { "Deprecated instruction" },
                Errors = new[] { "Syntax error on line 1", "Unknown instruction" }
            };

            _mockPayloadManager
                .Setup(x => x.CompilePayloadAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(compileResult);

            // Act
            var result = await _service.CompilePayloadAsync(sourcePath, outputPath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.False(result.Value.Success);
            Assert.NotEmpty(result.Value.Errors);
        }

        [Fact]
        public async Task GetCachedPayloadsAsync_ReturnsCachedPayloads()
        {
            // Arrange
            var cachedPayloads = new[]
            {
                new PayloadInfo { Name = "cached1.bin", Path = "/cache/cached1.bin", Size = 100 },
                new PayloadInfo { Name = "cached2.bin", Path = "/cache/cached2.bin", Size = 200 }
            };

            _mockPayloadManager
                .Setup(x => x.GetCachedPayloadsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(cachedPayloads);

            // Act
            var result = await _service.GetCachedPayloadsAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Equal(2, result.Value.Count());
        }

        [Fact]
        public async Task ClearPayloadCacheAsync_ReturnsSuccess()
        {
            // Arrange
            _mockPayloadManager
                .Setup(x => x.ClearCacheAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            // Act
            var result = await _service.ClearPayloadCacheAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task GetPayloadInfoAsync_WithValidPath_ReturnsInfo()
        {
            // Arrange
            var payloadPath = Path.Combine(_tempDirectory, "test.bin");
            var testData = new byte[] { 0x01, 0x02, 0x03, 0x04 };
            await File.WriteAllBytesAsync(payloadPath, testData);

            var payloadInfo = new PayloadInfo
            {
                Name = "test.bin",
                Path = payloadPath,
                Size = testData.Length,
                LastModified = DateTime.UtcNow,
                Description = "Test payload"
            };

            _mockPayloadManager
                .Setup(x => x.GetPayloadInfoAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(payloadInfo);

            // Act
            var result = await _service.GetPayloadInfoAsync(payloadPath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Equal("test.bin", result.Value.Name);
            Assert.Equal(testData.Length, result.Value.Size);
        }

        [Fact]
        public async Task GetPayloadInfoAsync_WithNullPath_ReturnsFailure()
        {
            // Arrange
            string payloadPath = null!;

            // Act
            var result = await _service.GetPayloadInfoAsync(payloadPath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload path cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task GetSupportedFormatsAsync_ReturnsFormats()
        {
            // Arrange
            var supportedFormats = new[] { ".bin", ".hex", ".elf", ".s" };

            _mockPayloadManager
                .Setup(x => x.GetSupportedFormatsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(supportedFormats);

            // Act
            var result = await _service.GetSupportedFormatsAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Contains(".bin", result.Value);
            Assert.Contains(".hex", result.Value);
            Assert.Contains(".elf", result.Value);
            Assert.Contains(".s", result.Value);
        }

        [Fact]
        public async Task GetPayloadStatisticsAsync_ReturnsStatistics()
        {
            // Arrange
            var statistics = new PayloadStatistics
            {
                TotalPayloads = 10,
                TotalSize = 1024000,
                CachedPayloads = 5,
                CacheSize = 512000,
                LastScanTime = DateTime.UtcNow.AddMinutes(-30)
            };

            _mockPayloadManager
                .Setup(x => x.GetStatisticsAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(statistics);

            // Act
            var result = await _service.GetPayloadStatisticsAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Equal(10, result.Value.TotalPayloads);
            Assert.Equal(1024000, result.Value.TotalSize);
        }

        private void CreateTestPayloadFiles()
        {
            var file1 = Path.Combine(_tempDirectory, "test1.bin");
            var file2 = Path.Combine(_tempDirectory, "test2.hex");
            
            File.WriteAllBytes(file1, new byte[100]);
            File.WriteAllBytes(file2, new byte[200]);
        }
    }
}