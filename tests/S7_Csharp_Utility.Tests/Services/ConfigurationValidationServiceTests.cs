using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using S7.Core.Abstractions.Configuration;
using S7.Services;
using S7.Utils;
using Xunit;

namespace S7_Csharp_Utility.Tests.Services
{
    /// <summary>
    /// Unit tests for ConfigurationValidationService to verify configuration validation functionality.
    /// </summary>
    public class ConfigurationValidationServiceTests
    {
        private readonly Mock<ILogger<ConfigurationValidationService>> _mockLogger;
        private readonly Mock<IOptions<ApplicationOptions>> _mockApplicationOptions;
        private readonly ConfigurationValidationService _service;

        public ConfigurationValidationServiceTests()
        {
            _mockLogger = new Mock<ILogger<ConfigurationValidationService>>();
            _mockApplicationOptions = new Mock<IOptions<ApplicationOptions>>();
            
            // Setup default valid configuration
            var validConfig = CreateValidApplicationOptions();
            _mockApplicationOptions.Setup(x => x.Value).Returns(validConfig);
            
            _service = new ConfigurationValidationService(_mockApplicationOptions.Object, _mockLogger.Object);
        }

        [Fact]
        public void Constructor_WithNullApplicationOptions_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new ConfigurationValidationService(null!, _mockLogger.Object));
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new ConfigurationValidationService(_mockApplicationOptions.Object, null!));
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithValidConfiguration_ReturnsSuccess()
        {
            // Arrange
            var validConfig = CreateValidApplicationOptions();
            _mockApplicationOptions.Setup(x => x.Value).Returns(validConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidPlcOperationTimeout_ReturnsFailure()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.PlcOperation!.DefaultTimeoutMs = -1; // Invalid timeout

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("timeout", result.Error.Message.ToLower());
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidMemoryDumpAddress_ReturnsFailure()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.MemoryDump!.DefaultStartAddress = 0; // Invalid address (should be > 0)

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("address", result.Error.Message.ToLower());
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithCommunicationChannelTimeoutLessThanPlcTimeout_ReturnsFailure()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.PlcOperation!.DefaultTimeoutMs = 10000;
            invalidConfig.CommunicationChannel!.ConnectionTimeoutMs = 5000; // Less than PLC timeout

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Communication channel connection timeout cannot be less than PLC operation default timeout", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithSocatEnabledButNoPath_ReturnsFailure()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.CommunicationChannel!.UseSocat = true;
            invalidConfig.CommunicationChannel.SocatPath = null; // Missing socat path

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Socat path must be specified when socat is enabled", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithStagerPowerCyclingButNoPowerSupply_ReturnsFailure()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.Stager!.EnablePowerCycling = true;
            invalidConfig.PowerSupply = null; // Missing power supply config

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Power supply configuration is required when stager power cycling is enabled", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithFileLoggingEnabledButNoPath_ReturnsFailure()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.Logging!.EnableFileLogging = true;
            invalidConfig.Logging.LogFilePath = null; // Missing log file path

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Log file path must be specified when file logging is enabled", result.Error.Message);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithCancellation_ThrowsOperationCanceledException()
        {
            // Arrange
            var cancellationTokenSource = new CancellationTokenSource();
            cancellationTokenSource.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() =>
                _service.ValidateConfigurationAsync(cancellationTokenSource.Token));
        }

        [Fact]
        public async Task ValidateConfigurationSectionAsync_WithValidSection_ReturnsSuccess()
        {
            // Arrange
            var validPlcOptions = new PlcOperationOptions
            {
                DefaultTimeoutMs = 30000,
                MaxRetryAttempts = 3,
                RetryDelayMs = 1000
            };

            // Act
            var result = await _service.ValidateConfigurationSectionAsync(validPlcOptions, "PlcOperationOptions", CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateConfigurationSectionAsync_WithNullSection_ReturnsSuccess()
        {
            // Arrange
            PlcOperationOptions nullSection = null!;

            // Act
            var result = await _service.ValidateConfigurationSectionAsync(nullSection, "PlcOperationOptions", CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value); // Null sections are considered valid (optional)
        }

        [Fact]
        public async Task GetValidationErrorsAsync_WithValidConfiguration_ReturnsEmptyList()
        {
            // Arrange
            var validConfig = CreateValidApplicationOptions();
            _mockApplicationOptions.Setup(x => x.Value).Returns(validConfig);

            // Act
            var result = await _service.GetValidationErrorsAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Empty(result.Value);
        }

        [Fact]
        public async Task GetValidationErrorsAsync_WithInvalidConfiguration_ReturnsErrors()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.PlcOperation!.DefaultTimeoutMs = -1; // Invalid timeout
            invalidConfig.MemoryDump!.DefaultStartAddress = 0; // Invalid address

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.GetValidationErrorsAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotEmpty(result.Value);
            Assert.Contains(result.Value, error => error.Contains("timeout"));
            Assert.Contains(result.Value, error => error.Contains("address"));
        }

        [Fact]
        public async Task IsConfigurationValidAsync_WithValidConfiguration_ReturnsTrue()
        {
            // Arrange
            var validConfig = CreateValidApplicationOptions();
            _mockApplicationOptions.Setup(x => x.Value).Returns(validConfig);

            // Act
            var result = await _service.IsConfigurationValidAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task IsConfigurationValidAsync_WithInvalidConfiguration_ReturnsFalse()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.PlcOperation!.DefaultTimeoutMs = -1; // Invalid timeout

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.IsConfigurationValidAsync(CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.False(result.Value);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithMultipleValidationErrors_ReturnsAllErrors()
        {
            // Arrange
            var invalidConfig = CreateValidApplicationOptions();
            invalidConfig.PlcOperation!.DefaultTimeoutMs = -1; // Error 1
            invalidConfig.MemoryDump!.DefaultStartAddress = 0; // Error 2
            invalidConfig.CommunicationChannel!.ConnectionTimeoutMs = 1000; // Error 3 (less than PLC timeout)
            invalidConfig.CommunicationChannel.UseSocat = true;
            invalidConfig.CommunicationChannel.SocatPath = null; // Error 4

            _mockApplicationOptions.Setup(x => x.Value).Returns(invalidConfig);

            // Act
            var result = await _service.ValidateConfigurationAsync(CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            var errorMessage = result.Error.Message;
            Assert.Contains("timeout", errorMessage.ToLower());
            Assert.Contains("address", errorMessage.ToLower());
            Assert.Contains("socat", errorMessage.ToLower());
        }

        private ApplicationOptions CreateValidApplicationOptions()
        {
            return new ApplicationOptions
            {
                PlcOperation = new PlcOperationOptions
                {
                    DefaultTimeoutMs = 30000,
                    MaxRetryAttempts = 3,
                    RetryDelayMs = 1000
                },
                MemoryDump = new MemoryDumpOptions
                {
                    DefaultStartAddress = 0x1000,
                    DefaultLength = 1024,
                    ChunkSize = 256,
                    VerifyDumps = true
                },
                Stager = new StagerOptions
                {
                    DefaultTimeoutMs = 60000,
                    EnablePowerCycling = false,
                    VerifyInstallation = true,
                    MaxRetryAttempts = 3
                },
                Payload = new PayloadOptions
                {
                    PayloadDirectory = "/path/to/payloads",
                    CacheEnabled = true,
                    MaxCacheSize = 100,
                    ScanOnStartup = true
                },
                CommunicationChannel = new CommunicationChannelOptions
                {
                    DefaultEndpoint = "192.168.1.100:102",
                    ConnectionTimeoutMs = 35000, // Greater than PLC timeout
                    UseSocat = false,
                    SocatPath = "/usr/bin/socat",
                    AutoDiscoverSerialPorts = true
                },
                PowerSupply = new PowerSupplyOptions
                {
                    Enabled = false,
                    Host = "192.168.1.200",
                    Port = 502,
                    SlaveId = 1,
                    ConnectionTimeoutMs = 5000
                },
                Logging = new LoggingOptions
                {
                    EnableFileLogging = false,
                    EnableConsoleLogging = true,
                    LogFilePath = "/var/log/s7bootloader.log",
                    FileLogLevel = Microsoft.Extensions.Logging.LogLevel.Information,
                    ConsoleLogLevel = Microsoft.Extensions.Logging.LogLevel.Information,
                    MaxLogFileSize = 10485760
                }
            };
        }
    }
}