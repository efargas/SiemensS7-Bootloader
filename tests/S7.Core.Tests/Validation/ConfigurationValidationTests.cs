using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Configuration;
using S7.Services;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace S7.Core.Tests.Validation
{
    /// <summary>
    /// Unit tests for configuration validation functionality.
    /// </summary>
    public class ConfigurationValidationTests
    {
        private readonly Mock<ILogger<ConfigurationValidationService>> _mockLogger;
        private readonly ConfigurationValidationService _validationService;

        public ConfigurationValidationTests()
        {
            _mockLogger = new Mock<ILogger<ConfigurationValidationService>>();
            _validationService = new ConfigurationValidationService(_mockLogger.Object);
        }

        #region Constructor Tests

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new ConfigurationValidationService(null!));
        }

        #endregion

        #region ValidateConfigurationAsync Tests

        [Fact]
        public async Task ValidateConfigurationAsync_WithValidConfiguration_ReturnsSuccess()
        {
            // Arrange
            var config = CreateValidApplicationOptions();

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithNullConfiguration_ReturnsFailure()
        {
            // Act
            var result = await _validationService.ValidateConfigurationAsync(null!, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Configuration cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidPlcOperationOptions_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.PlcOperation.DefaultTimeoutMs = -1; // Invalid timeout

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("DefaultTimeoutMs", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidMemoryDumpOptions_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.MemoryDump.DefaultChunkSize = 0; // Invalid chunk size

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("DefaultChunkSize", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidStagerOptions_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.Stager.MaxPayloadSize = -1; // Invalid payload size

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("MaxPayloadSize", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidPayloadOptions_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.Payload.ScanTimeoutMs = 0; // Invalid timeout

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("ScanTimeoutMs", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidCommunicationChannelOptions_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.CommunicationChannel.SocatTimeoutMs = -1; // Invalid timeout

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("SocatTimeoutMs", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidPowerSupplyOptions_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.PowerSupply.ModbusPort = 70000; // Invalid port number

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("ModbusPort", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidLoggingOptions_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.Logging.MaxFileSizeMB = -1; // Invalid file size

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("MaxFileSizeMB", result.Error.Message);
        }

        #endregion

        #region ValidateConfigurationSectionAsync Tests

        [Fact]
        public async Task ValidateConfigurationSectionAsync_WithValidSection_ReturnsSuccess()
        {
            // Arrange
            var plcOptions = new PlcOperationOptions
            {
                DefaultTimeoutMs = 30000,
                MaxRetries = 3,
                RetryDelayMs = 1000
            };

            // Act
            var result = await _validationService.ValidateConfigurationSectionAsync(plcOptions, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateConfigurationSectionAsync_WithNullSection_ReturnsFailure()
        {
            // Act
            var result = await _validationService.ValidateConfigurationSectionAsync<PlcOperationOptions>(null!, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Configuration section cannot be null", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationSectionAsync_WithInvalidSection_ReturnsFailure()
        {
            // Arrange
            var plcOptions = new PlcOperationOptions
            {
                DefaultTimeoutMs = -1, // Invalid
                MaxRetries = 3,
                RetryDelayMs = 1000
            };

            // Act
            var result = await _validationService.ValidateConfigurationSectionAsync(plcOptions, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("DefaultTimeoutMs", result.Error.Message);
        }

        #endregion

        #region GetValidationErrorsAsync Tests

        [Fact]
        public async Task GetValidationErrorsAsync_WithValidConfiguration_ReturnsEmptyList()
        {
            // Arrange
            var config = CreateValidApplicationOptions();

            // Act
            var result = await _validationService.GetValidationErrorsAsync(config, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Empty(result.Value);
        }

        [Fact]
        public async Task GetValidationErrorsAsync_WithInvalidConfiguration_ReturnsErrors()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.PlcOperation.DefaultTimeoutMs = -1; // Invalid
            config.MemoryDump.DefaultChunkSize = 0; // Invalid

            // Act
            var result = await _validationService.GetValidationErrorsAsync(config, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotEmpty(result.Value);
            Assert.Contains(result.Value, error => error.Contains("DefaultTimeoutMs"));
            Assert.Contains(result.Value, error => error.Contains("DefaultChunkSize"));
        }

        [Fact]
        public async Task GetValidationErrorsAsync_WithNullConfiguration_ReturnsError()
        {
            // Act
            var result = await _validationService.GetValidationErrorsAsync(null!, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Configuration cannot be null", result.Error.Message);
        }

        #endregion

        #region IsConfigurationValidAsync Tests

        [Fact]
        public async Task IsConfigurationValidAsync_WithValidConfiguration_ReturnsTrue()
        {
            // Arrange
            var config = CreateValidApplicationOptions();

            // Act
            var result = await _validationService.IsConfigurationValidAsync(config, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task IsConfigurationValidAsync_WithInvalidConfiguration_ReturnsFalse()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.PlcOperation.DefaultTimeoutMs = -1; // Invalid

            // Act
            var result = await _validationService.IsConfigurationValidAsync(config, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.False(result.Value);
        }

        [Fact]
        public async Task IsConfigurationValidAsync_WithNullConfiguration_ReturnsFailure()
        {
            // Act
            var result = await _validationService.IsConfigurationValidAsync(null!, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Configuration cannot be null", result.Error.Message);
        }

        #endregion

        #region Cross-Section Validation Tests

        [Fact]
        public async Task ValidateConfigurationAsync_WithInconsistentTimeouts_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.PlcOperation.DefaultTimeoutMs = 60000; // 1 minute
            config.CommunicationChannel.SocatTimeoutMs = 30000; // 30 seconds - should be >= PLC timeout

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Communication channel timeout", result.Error.Message);
            Assert.Contains("PLC operation timeout", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithSocatEnabledButNoPath_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.CommunicationChannel.EnableSocat = true;
            config.CommunicationChannel.SocatPath = null; // Missing path

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Socat path must be specified", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithPowerCyclingEnabledButNoPowerSupply_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.Stager.EnablePowerCycling = true;
            config.PowerSupply.ModbusHost = null; // Missing power supply configuration

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Power supply configuration required", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithFileLoggingEnabledButNoPath_ReturnsFailure()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            config.Logging.EnableFileLogging = true;
            config.Logging.LogFilePath = null; // Missing log file path

            // Act
            var result = await _validationService.ValidateConfigurationAsync(config, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Log file path must be specified", result.Error.Message);
        }

        #endregion

        #region Cancellation Tests

        [Fact]
        public async Task ValidateConfigurationAsync_WithCancellation_ThrowsOperationCanceledException()
        {
            // Arrange
            var config = CreateValidApplicationOptions();
            var cts = new CancellationTokenSource();
            cts.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _validationService.ValidateConfigurationAsync(config, cts.Token));
        }

        [Fact]
        public async Task ValidateConfigurationSectionAsync_WithCancellation_ThrowsOperationCanceledException()
        {
            // Arrange
            var plcOptions = new PlcOperationOptions
            {
                DefaultTimeoutMs = 30000,
                MaxRetries = 3,
                RetryDelayMs = 1000
            };
            var cts = new CancellationTokenSource();
            cts.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _validationService.ValidateConfigurationSectionAsync(plcOptions, cts.Token));
        }

        #endregion

        #region Helper Methods

        private static ApplicationOptions CreateValidApplicationOptions()
        {
            return new ApplicationOptions
            {
                PlcOperation = new PlcOperationOptions
                {
                    DefaultTimeoutMs = 30000,
                    MaxRetries = 3,
                    RetryDelayMs = 1000,
                    EnableDetailedLogging = true
                },
                MemoryDump = new MemoryDumpOptions
                {
                    DefaultChunkSize = 1024,
                    MaxDumpSize = 1024 * 1024,
                    EnableChecksumValidation = true,
                    DefaultOutputDirectory = "/tmp/dumps"
                },
                Stager = new StagerOptions
                {
                    MaxPayloadSize = 1024 * 1024,
                    DefaultInstallAddress = 0x20000000,
                    EnablePowerCycling = false,
                    PowerCycleDelayMs = 5000,
                    MaxInstallRetries = 3
                },
                Payload = new PayloadOptions
                {
                    ScanTimeoutMs = 10000,
                    MaxCacheSize = 100,
                    EnableCompilation = true,
                    PayloadDirectory = "/tmp/payloads",
                    CompilerPath = "/usr/bin/gcc"
                },
                CommunicationChannel = new CommunicationChannelOptions
                {
                    EnableSocat = false,
                    SocatPath = "/usr/bin/socat",
                    SocatTimeoutMs = 60000,
                    SerialPortBaudRate = 115200,
                    SerialPortTimeout = 5000
                },
                PowerSupply = new PowerSupplyOptions
                {
                    ModbusHost = "192.168.1.100",
                    ModbusPort = 502,
                    ModbusSlaveId = 1,
                    PowerOnCoil = 1,
                    PowerOffCoil = 2,
                    ConnectionTimeoutMs = 5000
                },
                Logging = new LoggingOptions
                {
                    EnableFileLogging = false,
                    LogFilePath = "/tmp/logs/app.log",
                    MaxFileSizeMB = 10,
                    MaxFileCount = 5,
                    ConsoleLogLevel = "Information",
                    FileLogLevel = "Debug"
                }
            };
        }

        #endregion
    }
}