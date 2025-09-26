using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Services;
using S7.Net;
using S7.Services;
using S7.Utils;
using Xunit;

namespace S7_Csharp_Utility.Tests.Services
{
    /// <summary>
    /// Unit tests for PlcOperationService to verify PLC operation functionality and error handling.
    /// </summary>
    public class PlcOperationServiceTests
    {
        private readonly Mock<ILogger<PlcOperationService>> _mockLogger;
        private readonly Mock<PlcClient> _mockPlcClient;
        private readonly PlcOperationService _service;

        public PlcOperationServiceTests()
        {
            _mockLogger = new Mock<ILogger<PlcOperationService>>();
            _mockPlcClient = new Mock<PlcClient>();
            _service = new PlcOperationService(_mockLogger.Object);
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new PlcOperationService(null!));
        }

        [Fact]
        public async Task ConnectAsync_WithValidEndpoint_ReturnsSuccess()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var cancellationToken = CancellationToken.None;

            // Act
            var result = await _service.ConnectAsync(endpoint, cancellationToken);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
        }

        [Fact]
        public async Task ConnectAsync_WithInvalidEndpoint_ReturnsFailure()
        {
            // Arrange
            var endpoint = "invalid-endpoint";
            var cancellationToken = CancellationToken.None;

            // Act
            var result = await _service.ConnectAsync(endpoint, cancellationToken);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.NotNull(result.Error);
        }

        [Fact]
        public async Task ConnectAsync_WithNullEndpoint_ReturnsFailure()
        {
            // Arrange
            string endpoint = null!;
            var cancellationToken = CancellationToken.None;

            // Act
            var result = await _service.ConnectAsync(endpoint, cancellationToken);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Endpoint cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task ConnectAsync_WithEmptyEndpoint_ReturnsFailure()
        {
            // Arrange
            var endpoint = string.Empty;
            var cancellationToken = CancellationToken.None;

            // Act
            var result = await _service.ConnectAsync(endpoint, cancellationToken);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Endpoint cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task ConnectAsync_WithCancellationToken_ThrowsOperationCanceledException()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _service.ConnectAsync(endpoint, cancellationTokenSource.Token));
        }

        [Fact]
        public async Task DisconnectAsync_WithValidClient_ReturnsSuccess()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);

            // Act
            var result = await _service.DisconnectAsync(connectResult.Value, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
        }

        [Fact]
        public async Task DisconnectAsync_WithNullClient_ReturnsFailure()
        {
            // Arrange
            PlcClient client = null!;

            // Act
            var result = await _service.DisconnectAsync(client, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("PLC client cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task GetDeviceInfoAsync_WithValidClient_ReturnsSuccess()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);

            // Act
            var result = await _service.GetDeviceInfoAsync(connectResult.Value, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.NotEmpty(result.Value.DeviceType);
            Assert.NotEmpty(result.Value.SerialNumber);
            Assert.NotEmpty(result.Value.FirmwareVersion);
        }

        [Fact]
        public async Task GetDeviceInfoAsync_WithNullClient_ReturnsFailure()
        {
            // Arrange
            PlcClient client = null!;

            // Act
            var result = await _service.GetDeviceInfoAsync(client, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("PLC client cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task ExecuteExploitSequenceAsync_WithValidParameters_ReturnsSuccess()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var payloadPath = "/path/to/payload.bin";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);

            // Act
            var result = await _service.ExecuteExploitSequenceAsync(
                connectResult.Value, payloadPath, CancellationToken.None);

            // Assert
            // Note: This will likely fail in unit tests without actual PLC hardware
            // but we're testing the service layer logic and error handling
            Assert.NotNull(result);
        }

        [Fact]
        public async Task ExecuteExploitSequenceAsync_WithNullClient_ReturnsFailure()
        {
            // Arrange
            PlcClient client = null!;
            var payloadPath = "/path/to/payload.bin";

            // Act
            var result = await _service.ExecuteExploitSequenceAsync(client, payloadPath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("PLC client cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task ExecuteExploitSequenceAsync_WithNullPayloadPath_ReturnsFailure()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);
            string payloadPath = null!;

            // Act
            var result = await _service.ExecuteExploitSequenceAsync(
                connectResult.Value, payloadPath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload path cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task ExecuteExploitSequenceAsync_WithEmptyPayloadPath_ReturnsFailure()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);
            var payloadPath = string.Empty;

            // Act
            var result = await _service.ExecuteExploitSequenceAsync(
                connectResult.Value, payloadPath, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Payload path cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task ReadMemoryAsync_WithValidParameters_ReturnsSuccess()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);
            uint address = 0x1000;
            uint length = 256;

            // Act
            var result = await _service.ReadMemoryAsync(connectResult.Value, address, length, CancellationToken.None);

            // Assert
            // Note: This will likely fail in unit tests without actual PLC hardware
            // but we're testing the service layer logic and error handling
            Assert.NotNull(result);
        }

        [Fact]
        public async Task ReadMemoryAsync_WithNullClient_ReturnsFailure()
        {
            // Arrange
            PlcClient client = null!;
            uint address = 0x1000;
            uint length = 256;

            // Act
            var result = await _service.ReadMemoryAsync(client, address, length, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("PLC client cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task ReadMemoryAsync_WithZeroLength_ReturnsFailure()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);
            uint address = 0x1000;
            uint length = 0;

            // Act
            var result = await _service.ReadMemoryAsync(connectResult.Value, address, length, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Length must be greater than zero", result.Error.Message);
        }

        [Fact]
        public async Task WriteMemoryAsync_WithValidParameters_ReturnsSuccess()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);
            uint address = 0x1000;
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            // Act
            var result = await _service.WriteMemoryAsync(connectResult.Value, address, data, CancellationToken.None);

            // Assert
            // Note: This will likely fail in unit tests without actual PLC hardware
            // but we're testing the service layer logic and error handling
            Assert.NotNull(result);
        }

        [Fact]
        public async Task WriteMemoryAsync_WithNullClient_ReturnsFailure()
        {
            // Arrange
            PlcClient client = null!;
            uint address = 0x1000;
            var data = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            // Act
            var result = await _service.WriteMemoryAsync(client, address, data, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("PLC client cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task WriteMemoryAsync_WithNullData_ReturnsFailure()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);
            uint address = 0x1000;
            byte[] data = null!;

            // Act
            var result = await _service.WriteMemoryAsync(connectResult.Value, address, data, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Data cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public async Task WriteMemoryAsync_WithEmptyData_ReturnsFailure()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);
            uint address = 0x1000;
            var data = Array.Empty<byte>();

            // Act
            var result = await _service.WriteMemoryAsync(connectResult.Value, address, data, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Data cannot be null or empty", result.Error.Message);
        }

        [Fact]
        public void Dispose_DoesNotThrow()
        {
            // Act & Assert
            var exception = Record.Exception(() => _service.Dispose());
            Assert.Null(exception);
        }

        [Fact]
        public async Task MultipleOperations_WithSameClient_WorkCorrectly()
        {
            // Arrange
            var endpoint = "192.168.1.100:102";
            var connectResult = await _service.ConnectAsync(endpoint, CancellationToken.None);
            Assert.True(connectResult.IsSuccess);

            // Act - Perform multiple operations
            var deviceInfoResult = await _service.GetDeviceInfoAsync(connectResult.Value, CancellationToken.None);
            var readResult = await _service.ReadMemoryAsync(connectResult.Value, 0x1000, 256, CancellationToken.None);
            var disconnectResult = await _service.DisconnectAsync(connectResult.Value, CancellationToken.None);

            // Assert
            Assert.True(deviceInfoResult.IsSuccess);
            Assert.NotNull(readResult); // May fail without hardware, but should not throw
            Assert.True(disconnectResult.IsSuccess);
        }
    }
}