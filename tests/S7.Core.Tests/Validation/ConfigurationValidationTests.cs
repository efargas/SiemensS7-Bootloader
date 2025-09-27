using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using S7.Core.Abstractions.Configuration;
using S7.Services;
using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace S7.Core.Tests.Validation
{
    public class ConfigurationValidationTests
    {
        private readonly Mock<ILogger<ConfigurationValidationService>> _mockLogger;

        public ConfigurationValidationTests()
        {
            _mockLogger = new Mock<ILogger<ConfigurationValidationService>>();
        }

        private IOptions<ApplicationOptions> CreateOptions(ApplicationOptions options)
        {
            return Options.Create(options);
        }

        private ApplicationOptions CreateValidApplicationOptions()
        {
            // Create a default valid configuration
            return new ApplicationOptions
            {
                PlcOperations = new PlcOperationOptions(),
                MemoryDump = new MemoryDumpOptions(),
                Stager = new StagerOptions(),
                Payload = new PayloadOptions(),
                CommunicationChannel = new CommunicationChannelOptions(),
                PowerSupply = new PowerSupplyOptions(),
                Logging = new LoggingOptions()
            };
        }

        [Fact]
        public void Constructor_WithNullOptions_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new ConfigurationValidationService(null!, _mockLogger.Object));
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Arrange
            var options = CreateOptions(new ApplicationOptions());

            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new ConfigurationValidationService(options, null!));
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithValidConfiguration_ReturnsSuccess()
        {
            // Arrange
            var options = CreateOptions(CreateValidApplicationOptions());
            var service = new ConfigurationValidationService(options, _mockLogger.Object);

            // Act
            var result = await service.ValidateConfigurationAsync();

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateConfigurationAsync_WithInvalidPlcOperations_ReturnsFailure()
        {
            // Arrange
            var appOptions = CreateValidApplicationOptions();
            appOptions.PlcOperations.ConnectionTimeoutMs = -1; // Invalid value
            var options = CreateOptions(appOptions);
            var service = new ConfigurationValidationService(options, _mockLogger.Object);

            // Act
            var result = await service.ValidateConfigurationAsync();

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("ConnectionTimeoutMs", result.Error.Message);
        }

        [Fact]
        public async Task GetValidationErrorsAsync_WithInvalidConfiguration_ReturnsErrors()
        {
            // Arrange
            var appOptions = CreateValidApplicationOptions();
            appOptions.PlcOperations.ConnectionTimeoutMs = -1; // Invalid
            appOptions.MemoryDump.DefaultDumpSize = 0;      // Invalid
            var options = CreateOptions(appOptions);
            var service = new ConfigurationValidationService(options, _mockLogger.Object);

            // Act
            var result = await service.GetValidationErrorsAsync();

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.True(result.Value.Count >= 2);
            Assert.Contains(result.Value, e => e.Contains("ConnectionTimeoutMs"));
            Assert.Contains(result.Value, e => e.Contains("DefaultDumpSize"));
        }
    }
}