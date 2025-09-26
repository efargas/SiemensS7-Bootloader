using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Services;
using S7.Net;
using S7.Services;
using S7.Utils;
using Xunit;

namespace S7_Csharp_Utility.Tests.Services
{
    /// <summary>
    /// Unit tests for MemoryDumpService to verify memory dump functionality and error handling.
    /// </summary>
    public class MemoryDumpServiceTests : IDisposable
    {
        private readonly Mock<ILogger<MemoryDumpService>> _mockLogger;
        private readonly Mock<IPlcOperationService> _mockPlcOperationService;
        private readonly MemoryDumpService _service;
        private readonly string _tempDirectory;

        public MemoryDumpServiceTests()
        {
            _mockLogger = new Mock<ILogger<MemoryDumpService>>();
            _mockPlcOperationService = new Mock<IPlcOperationService>();
            _service = new MemoryDumpService(_mockLogger.Object, _mockPlcOperationService.Object);
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
                new MemoryDumpService(null!, _mockPlcOperationService.Object));
        }

        [Fact]
        public void Constructor_WithNullPlcOperationService_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new MemoryDumpService(_mockLogger.Object, null!));
        }

        [Fact]
        public async Task DumpMemoryAsync_WithValidOptions_ReturnsSuccess()
        {
            // Arrange
            var options = CreateValidMemoryDumpOptions();
            var mockPlcClient = new Mock<PlcClient>();
            var mockProgress = new Mock<IProgress<MemoryDumpProgress>>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            _mockPlcOperationService
                .Setup(x => x.ReadMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<uint>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<byte[]>.Success(new byte[1024]));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.DumpMemoryAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.True(result.Value.Success);
            Assert.Equal(options.Length, result.Value.BytesDumped);
        }

        [Fact]
        public async Task DumpMemoryAsync_WithNullOptions_ReturnsFailure()
        {
            // Arrange
            MemoryDumpOptions options = null!;
            var mockProgress = new Mock<IProgress<MemoryDumpProgress>>();

            // Act
            var result = await _service.DumpMemoryAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Options cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task DumpMemoryAsync_WithInvalidOutputPath_ReturnsFailure()
        {
            // Arrange
            var options = CreateValidMemoryDumpOptions();
            options.OutputPath = "/invalid/path/that/does/not/exist";
            var mockProgress = new Mock<IProgress<MemoryDumpProgress>>();

            // Act
            var result = await _service.DumpMemoryAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Output directory does not exist", result.Error.Message);
        }

        [Fact]
        public async Task DumpMemoryAsync_WithConnectionFailure_ReturnsFailure()
        {
            // Arrange
            var options = CreateValidMemoryDumpOptions();
            var mockProgress = new Mock<IProgress<MemoryDumpProgress>>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Failure(new Exception("Connection failed")));

            // Act
            var result = await _service.DumpMemoryAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Connection failed", result.Error.Message);
        }

        [Fact]
        public async Task DumpMemoryAsync_WithReadMemoryFailure_ReturnsFailure()
        {
            // Arrange
            var options = CreateValidMemoryDumpOptions();
            var mockPlcClient = new Mock<PlcClient>();
            var mockProgress = new Mock<IProgress<MemoryDumpProgress>>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            _mockPlcOperationService
                .Setup(x => x.ReadMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<uint>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<byte[]>.Failure(new Exception("Read memory failed")));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.DumpMemoryAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Read memory failed", result.Error.Message);
        }

        [Fact]
        public async Task DumpMemoryAsync_WithCancellation_ThrowsOperationCanceledException()
        {
            // Arrange
            var options = CreateValidMemoryDumpOptions();
            var mockProgress = new Mock<IProgress<MemoryDumpProgress>>();
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _service.DumpMemoryAsync(options, mockProgress.Object, cancellationTokenSource.Token));
        }

        [Fact]
        public async Task DumpMemoryAsync_WithProgressReporting_ReportsProgress()
        {
            // Arrange
            var options = CreateValidMemoryDumpOptions();
            var mockPlcClient = new Mock<PlcClient>();
            var progressReports = new List<MemoryDumpProgress>();
            var progress = new Progress<MemoryDumpProgress>(p => progressReports.Add(p));

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            _mockPlcOperationService
                .Setup(x => x.ReadMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<uint>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<byte[]>.Success(new byte[1024]));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.DumpMemoryAsync(options, progress, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotEmpty(progressReports);
            Assert.Contains(progressReports, p => p.Stage == MemoryDumpStage.Connecting);
            Assert.Contains(progressReports, p => p.Stage == MemoryDumpStage.Reading);
            Assert.Contains(progressReports, p => p.Stage == MemoryDumpStage.Writing);
            Assert.Contains(progressReports, p => p.Stage == MemoryDumpStage.Completed);
        }

        [Fact]
        public async Task ValidateDumpAsync_WithValidFile_ReturnsSuccess()
        {
            // Arrange
            var dumpFilePath = Path.Combine(_tempDirectory, "test_dump.bin");
            var testData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            await File.WriteAllBytesAsync(dumpFilePath, testData);

            // Act
            var result = await _service.ValidateDumpAsync(dumpFilePath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value.IsValid);
            Assert.Equal(testData.Length, result.Value.FileSize);
        }

        [Fact]
        public async Task ValidateDumpAsync_WithNonExistentFile_ReturnsFailure()
        {
            // Arrange
            var dumpFilePath = Path.Combine(_tempDirectory, "nonexistent.bin");

            // Act
            var result = await _service.ValidateDumpAsync(dumpFilePath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("File does not exist", result.Error.Message);
        }

        [Fact]
        public async Task ValidateDumpAsync_WithNullFilePath_ReturnsFailure()
        {
            // Arrange
            string dumpFilePath = null!;

            // Act
            var result = await _service.ValidateDumpAsync(dumpFilePath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("File path cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task CompareDumpsAsync_WithIdenticalFiles_ReturnsNoDifferences()
        {
            // Arrange
            var testData = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            var file1Path = Path.Combine(_tempDirectory, "dump1.bin");
            var file2Path = Path.Combine(_tempDirectory, "dump2.bin");
            
            await File.WriteAllBytesAsync(file1Path, testData);
            await File.WriteAllBytesAsync(file2Path, testData);

            // Act
            var result = await _service.CompareDumpsAsync(file1Path, file2Path, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Empty(result.Value.Differences);
            Assert.True(result.Value.AreIdentical);
        }

        [Fact]
        public async Task CompareDumpsAsync_WithDifferentFiles_ReturnsDifferences()
        {
            // Arrange
            var testData1 = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            var testData2 = new byte[] { 0x01, 0x02, 0xFF, 0x04, 0x05 }; // Different byte at index 2
            var file1Path = Path.Combine(_tempDirectory, "dump1.bin");
            var file2Path = Path.Combine(_tempDirectory, "dump2.bin");
            
            await File.WriteAllBytesAsync(file1Path, testData1);
            await File.WriteAllBytesAsync(file2Path, testData2);

            // Act
            var result = await _service.CompareDumpsAsync(file1Path, file2Path, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotEmpty(result.Value.Differences);
            Assert.False(result.Value.AreIdentical);
            Assert.Contains(result.Value.Differences, d => d.Offset == 2);
        }

        [Fact]
        public async Task CompareDumpsAsync_WithNonExistentFile_ReturnsFailure()
        {
            // Arrange
            var file1Path = Path.Combine(_tempDirectory, "existing.bin");
            var file2Path = Path.Combine(_tempDirectory, "nonexistent.bin");
            
            await File.WriteAllBytesAsync(file1Path, new byte[] { 0x01, 0x02, 0x03 });

            // Act
            var result = await _service.CompareDumpsAsync(file1Path, file2Path, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("does not exist", result.Error.Message);
        }

        [Fact]
        public async Task AnalyzeDumpAsync_WithValidFile_ReturnsAnalysis()
        {
            // Arrange
            var testData = new byte[1024];
            // Fill with some pattern
            for (int i = 0; i < testData.Length; i++)
            {
                testData[i] = (byte)(i % 256);
            }
            
            var dumpFilePath = Path.Combine(_tempDirectory, "test_dump.bin");
            await File.WriteAllBytesAsync(dumpFilePath, testData);

            // Act
            var result = await _service.AnalyzeDumpAsync(dumpFilePath, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Equal(testData.Length, result.Value.FileSize);
            Assert.NotNull(result.Value.Statistics);
            Assert.NotNull(result.Value.Patterns);
        }

        [Fact]
        public async Task AnalyzeDumpAsync_WithNonExistentFile_ReturnsFailure()
        {
            // Arrange
            var dumpFilePath = Path.Combine(_tempDirectory, "nonexistent.bin");

            // Act
            var result = await _service.AnalyzeDumpAsync(dumpFilePath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("File does not exist", result.Error.Message);
        }

        [Fact]
        public async Task GetDumpHistoryAsync_ReturnsHistory()
        {
            // Arrange
            // Create some test dump files
            var dump1Path = Path.Combine(_tempDirectory, "dump1.bin");
            var dump2Path = Path.Combine(_tempDirectory, "dump2.bin");
            
            await File.WriteAllBytesAsync(dump1Path, new byte[] { 0x01, 0x02, 0x03 });
            await File.WriteAllBytesAsync(dump2Path, new byte[] { 0x04, 0x05, 0x06 });

            // Act
            var result = await _service.GetDumpHistoryAsync(_tempDirectory, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.NotEmpty(result.Value);
        }

        [Fact]
        public async Task GetDumpHistoryAsync_WithNonExistentDirectory_ReturnsFailure()
        {
            // Arrange
            var nonExistentDirectory = Path.Combine(_tempDirectory, "nonexistent");

            // Act
            var result = await _service.GetDumpHistoryAsync(nonExistentDirectory, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Directory does not exist", result.Error.Message);
        }

        private MemoryDumpOptions CreateValidMemoryDumpOptions()
        {
            return new MemoryDumpOptions
            {
                Address = 0x1000,
                Length = 1024,
                PayloadPath = "/path/to/payload.bin",
                OutputPath = _tempDirectory,
                ChannelConfig = new S7.Core.Abstractions.Configuration.CommunicationChannelConfig
                {
                    Endpoint = "192.168.1.100:102",
                    ConnectionTimeoutMs = 5000
                },
                ChunkSize = 256,
                TimeoutMs = 30000,
                VerifyDump = true,
                ValidateChecksum = true
            };
        }
    }
}