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
    /// Unit tests for StagerService to verify stager installation functionality and error handling.
    /// </summary>
    public class StagerServiceTests : IDisposable
    {
        private readonly Mock<ILogger<StagerService>> _mockLogger;
        private readonly Mock<IPlcOperationService> _mockPlcOperationService;
        private readonly Mock<IPowerSupplyService> _mockPowerSupplyService;
        private readonly StagerService _service;
        private readonly string _tempDirectory;

        public StagerServiceTests()
        {
            _mockLogger = new Mock<ILogger<StagerService>>();
            _mockPlcOperationService = new Mock<IPlcOperationService>();
            _mockPowerSupplyService = new Mock<IPowerSupplyService>();
            _service = new StagerService(_mockLogger.Object, _mockPlcOperationService.Object, _mockPowerSupplyService.Object);
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
                new StagerService(null!, _mockPlcOperationService.Object, _mockPowerSupplyService.Object));
        }

        [Fact]
        public void Constructor_WithNullPlcOperationService_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new StagerService(_mockLogger.Object, null!, _mockPowerSupplyService.Object));
        }

        [Fact]
        public void Constructor_WithNullPowerSupplyService_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new StagerService(_mockLogger.Object, _mockPlcOperationService.Object, null!));
        }

        [Fact]
        public async Task InstallStagerAsync_WithValidOptions_ReturnsSuccess()
        {
            // Arrange
            var options = CreateValidStagerInstallOptions();
            var mockPlcClient = new Mock<PlcClient>();
            var mockProgress = new Mock<IProgress<StagerInstallProgress>>();

            SetupSuccessfulInstallation(mockPlcClient.Object);

            // Act
            var result = await _service.InstallStagerAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.True(result.Value.Success);
            Assert.NotNull(result.Value.InstallationId);
        }

        [Fact]
        public async Task InstallStagerAsync_WithNullOptions_ReturnsFailure()
        {
            // Arrange
            StagerInstallOptions options = null!;
            var mockProgress = new Mock<IProgress<StagerInstallProgress>>();

            // Act
            var result = await _service.InstallStagerAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Options cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task InstallStagerAsync_WithNonExistentPayload_ReturnsFailure()
        {
            // Arrange
            var options = CreateValidStagerInstallOptions();
            options.PayloadPath = "/path/to/nonexistent/payload.bin";
            var mockProgress = new Mock<IProgress<StagerInstallProgress>>();

            // Act
            var result = await _service.InstallStagerAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload file does not exist", result.Error.Message);
        }

        [Fact]
        public async Task InstallStagerAsync_WithConnectionFailure_ReturnsFailure()
        {
            // Arrange
            var options = CreateValidStagerInstallOptions();
            var mockProgress = new Mock<IProgress<StagerInstallProgress>>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Failure(new Exception("Connection failed")));

            // Act
            var result = await _service.InstallStagerAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Connection failed", result.Error.Message);
        }

        [Fact]
        public async Task InstallStagerAsync_WithPowerCycling_CallsPowerSupplyService()
        {
            // Arrange
            var options = CreateValidStagerInstallOptions();
            options.PowerCycleBeforeInstall = true;
            options.PowerCycleAfterInstall = true;
            options.PowerConfig = new S7.Core.Abstractions.Configuration.PowerControllerConfig
            {
                Enabled = true,
                Host = "192.168.1.200",
                Port = 502
            };

            var mockPlcClient = new Mock<PlcClient>();
            var mockProgress = new Mock<IProgress<StagerInstallProgress>>();

            SetupSuccessfulInstallation(mockPlcClient.Object);
            SetupSuccessfulPowerCycling();

            // Act
            var result = await _service.InstallStagerAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            _mockPowerSupplyService.Verify(x => x.PowerCycleAsync(It.IsAny<CancellationToken>()), Times.AtLeast(1));
        }

        [Fact]
        public async Task InstallStagerAsync_WithRetryOnFailure_RetriesInstallation()
        {
            // Arrange
            var options = CreateValidStagerInstallOptions();
            options.RetryAttempts = 2;
            var mockPlcClient = new Mock<PlcClient>();
            var mockProgress = new Mock<IProgress<StagerInstallProgress>>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            // First attempt fails, second succeeds
            _mockPlcOperationService
                .SetupSequence(x => x.ExecuteExploitSequenceAsync(It.IsAny<PlcClient>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Failure(new Exception("Installation failed")))
                .ReturnsAsync(Result<bool>.Success(true));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.InstallStagerAsync(options, mockProgress.Object, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            _mockPlcOperationService.Verify(x => x.ExecuteExploitSequenceAsync(It.IsAny<PlcClient>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Exactly(2));
        }

        [Fact]
        public async Task InstallStagerAsync_WithCancellation_ThrowsOperationCanceledException()
        {
            // Arrange
            var options = CreateValidStagerInstallOptions();
            var mockProgress = new Mock<IProgress<StagerInstallProgress>>();
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _service.InstallStagerAsync(options, mockProgress.Object, cancellationTokenSource.Token));
        }

        [Fact]
        public async Task VerifyStagerAsync_WithValidStager_ReturnsSuccess()
        {
            // Arrange
            var installationId = Guid.NewGuid().ToString();
            var mockPlcClient = new Mock<PlcClient>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            _mockPlcOperationService
                .Setup(x => x.ReadMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<uint>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<byte[]>.Success(new byte[] { 0x01, 0x02, 0x03, 0x04 }));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.VerifyStagerAsync(installationId, "192.168.1.100:102", CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value.IsValid);
        }

        [Fact]
        public async Task VerifyStagerAsync_WithNullInstallationId_ReturnsFailure()
        {
            // Arrange
            string installationId = null!;

            // Act
            var result = await _service.VerifyStagerAsync(installationId, "192.168.1.100:102", CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Installation ID cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task ExecuteStagerCommandAsync_WithValidCommand_ReturnsSuccess()
        {
            // Arrange
            var installationId = Guid.NewGuid().ToString();
            var command = "test_command";
            var mockPlcClient = new Mock<PlcClient>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            _mockPlcOperationService
                .Setup(x => x.WriteMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            _mockPlcOperationService
                .Setup(x => x.ReadMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<uint>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<byte[]>.Success(System.Text.Encoding.UTF8.GetBytes("Command executed successfully")));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.ExecuteStagerCommandAsync(installationId, command, "192.168.1.100:102", CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Contains("Command executed successfully", result.Value.Output);
        }

        [Fact]
        public async Task ExecuteStagerCommandAsync_WithNullCommand_ReturnsFailure()
        {
            // Arrange
            var installationId = Guid.NewGuid().ToString();
            string command = null!;

            // Act
            var result = await _service.ExecuteStagerCommandAsync(installationId, command, "192.168.1.100:102", CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Command cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task GetStagerStatusAsync_WithValidInstallation_ReturnsStatus()
        {
            // Arrange
            var installationId = Guid.NewGuid().ToString();
            var mockPlcClient = new Mock<PlcClient>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            _mockPlcOperationService
                .Setup(x => x.ReadMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<uint>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<byte[]>.Success(new byte[] { 0x01 })); // Status: Running

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.GetStagerStatusAsync(installationId, "192.168.1.100:102", CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.Equal(StagerStatus.Running, result.Value.Status);
        }

        [Fact]
        public async Task UninstallStagerAsync_WithValidInstallation_ReturnsSuccess()
        {
            // Arrange
            var installationId = Guid.NewGuid().ToString();
            var mockPlcClient = new Mock<PlcClient>();

            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient.Object));

            _mockPlcOperationService
                .Setup(x => x.WriteMemoryAsync(It.IsAny<PlcClient>(), It.IsAny<uint>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            // Act
            var result = await _service.UninstallStagerAsync(installationId, "192.168.1.100:102", CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task GetInstallationHistoryAsync_ReturnsHistory()
        {
            // Act
            var result = await _service.GetInstallationHistoryAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
        }

        private StagerInstallOptions CreateValidStagerInstallOptions()
        {
            // Create a temporary payload file
            var payloadPath = Path.Combine(_tempDirectory, "test_payload.bin");
            File.WriteAllBytes(payloadPath, new byte[] { 0x01, 0x02, 0x03, 0x04 });

            return new StagerInstallOptions
            {
                PayloadPath = payloadPath,
                ChannelConfig = new S7.Core.Abstractions.Configuration.CommunicationChannelConfig
                {
                    Endpoint = "192.168.1.100:102",
                    ConnectionTimeoutMs = 5000
                },
                TimeoutMs = 30000,
                RetryAttempts = 1,
                RetryDelayMs = 1000,
                VerifyInstallation = true,
                TargetAddress = 0x1000,
                MaxPayloadSize = 1048576,
                BackupBeforeInstall = false,
                PerformIntegrityCheck = true,
                InstallationMode = StagerInstallationMode.Standard
            };
        }

        private void SetupSuccessfulInstallation(PlcClient mockPlcClient)
        {
            _mockPlcOperationService
                .Setup(x => x.ConnectAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<PlcClient>.Success(mockPlcClient));

            _mockPlcOperationService
                .Setup(x => x.ExecuteExploitSequenceAsync(It.IsAny<PlcClient>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            _mockPlcOperationService
                .Setup(x => x.DisconnectAsync(It.IsAny<PlcClient>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));
        }

        private void SetupSuccessfulPowerCycling()
        {
            _mockPowerSupplyService
                .Setup(x => x.PowerCycleAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));
        }
    }
}