using System;
using System.Globalization;
using FluentAssertions;
using S7_Csharp_Utility.Services;
using Xunit;

namespace S7_Csharp_Utility.Tests.Services
{
    /// <summary>
    /// Unit tests for ResourceManagerService.
    /// </summary>
    public class ResourceManagerServiceTests
    {
        private readonly ResourceManagerService _resourceManager;

        public ResourceManagerServiceTests()
        {
            _resourceManager = new ResourceManagerService();
        }

        [Fact]
        public void Constructor_ShouldInitializeSuccessfully()
        {
            // Act & Assert
            _resourceManager.Should().NotBeNull();
        }

        [Theory]
        [InlineData("Connection_Established")]
        [InlineData("Connection_Failed")]
        [InlineData("Memory_Dump_Started")]
        [InlineData("Handshake_Started")]
        [InlineData("Application_Starting")]
        public void GetLogMessage_WithValidKey_ShouldReturnMessage(string key)
        {
            // Act
            var result = _resourceManager.GetLogMessage(key);

            // Assert
            result.Should().NotBeNullOrEmpty();
            result.Should().NotBe(key); // Should return actual message, not the key
        }

        [Theory]
        [InlineData("Validation_Required_Field")]
        [InlineData("Connection_Timeout")]
        [InlineData("Protocol_Error")]
        [InlineData("Memory_Access_Denied")]
        [InlineData("Configuration_Invalid")]
        public void GetErrorMessage_WithValidKey_ShouldReturnMessage(string key)
        {
            // Act
            var result = _resourceManager.GetErrorMessage(key);

            // Assert
            result.Should().NotBeNullOrEmpty();
            result.Should().NotBe(key); // Should return actual message, not the key
        }

        [Fact]
        public void GetLogMessage_WithInvalidKey_ShouldReturnKey()
        {
            // Arrange
            const string invalidKey = "NonExistent_Key";

            // Act
            var result = _resourceManager.GetLogMessage(invalidKey);

            // Assert
            result.Should().Be(invalidKey); // Should return key as fallback
        }

        [Fact]
        public void GetErrorMessage_WithInvalidKey_ShouldReturnKey()
        {
            // Arrange
            const string invalidKey = "NonExistent_Error_Key";

            // Act
            var result = _resourceManager.GetErrorMessage(invalidKey);

            // Assert
            result.Should().Be(invalidKey); // Should return key as fallback
        }

        [Fact]
        public void GetLogMessage_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            _resourceManager.Invoking(rm => rm.GetLogMessage(null!))
                .Should().Throw<ArgumentNullException>()
                .WithParameterName("key");
        }

        [Fact]
        public void GetErrorMessage_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            _resourceManager.Invoking(rm => rm.GetErrorMessage(null!))
                .Should().Throw<ArgumentNullException>()
                .WithParameterName("key");
        }

        [Fact]
        public void GetFormattedLogMessage_WithValidKeyAndArgs_ShouldReturnFormattedMessage()
        {
            // Arrange
            const string key = "Connection_Established";
            const string plcAddress = "192.168.1.100";

            // Act
            var result = _resourceManager.GetFormattedLogMessage(key, plcAddress);

            // Assert
            result.Should().NotBeNullOrEmpty();
            result.Should().Contain(plcAddress);
        }

        [Fact]
        public void GetFormattedErrorMessage_WithValidKeyAndArgs_ShouldReturnFormattedMessage()
        {
            // Arrange
            const string key = "Connection_Failed";
            const string plcAddress = "192.168.1.100";
            const string errorMessage = "Connection refused";

            // Act
            var result = _resourceManager.GetFormattedErrorMessage(key, plcAddress, errorMessage);

            // Assert
            result.Should().NotBeNullOrEmpty();
            result.Should().Contain(plcAddress);
            result.Should().Contain(errorMessage);
        }

        [Fact]
        public void GetFormattedLogMessage_WithNoArgs_ShouldReturnUnformattedMessage()
        {
            // Arrange
            const string key = "Application_Starting";

            // Act
            var result = _resourceManager.GetFormattedLogMessage(key);

            // Assert
            result.Should().NotBeNullOrEmpty();
            result.Should().Be(_resourceManager.GetLogMessage(key));
        }

        [Fact]
        public void GetFormattedLogMessage_WithInvalidKey_ShouldReturnKeyWithArgs()
        {
            // Arrange
            const string invalidKey = "Invalid_Key";
            const string arg1 = "test1";
            const string arg2 = "test2";

            // Act
            var result = _resourceManager.GetFormattedLogMessage(invalidKey, arg1, arg2);

            // Assert
            result.Should().Contain(invalidKey);
            result.Should().Contain(arg1);
            result.Should().Contain(arg2);
        }

        [Fact]
        public void GetFormattedLogMessage_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            _resourceManager.Invoking(rm => rm.GetFormattedLogMessage(null!, "arg1"))
                .Should().Throw<ArgumentNullException>()
                .WithParameterName("key");
        }

        [Fact]
        public void GetFormattedErrorMessage_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            _resourceManager.Invoking(rm => rm.GetFormattedErrorMessage(null!, "arg1"))
                .Should().Throw<ArgumentNullException>()
                .WithParameterName("key");
        }

        [Theory]
        [InlineData("Connection_Established")]
        [InlineData("Memory_Dump_Started")]
        [InlineData("Application_Starting")]
        public void LogMessageExists_WithValidKey_ShouldReturnTrue(string key)
        {
            // Act
            var result = _resourceManager.LogMessageExists(key);

            // Assert
            result.Should().BeTrue();
        }

        [Theory]
        [InlineData("Validation_Required_Field")]
        [InlineData("Connection_Timeout")]
        [InlineData("Protocol_Error")]
        public void ErrorMessageExists_WithValidKey_ShouldReturnTrue(string key)
        {
            // Act
            var result = _resourceManager.ErrorMessageExists(key);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void LogMessageExists_WithInvalidKey_ShouldReturnFalse()
        {
            // Arrange
            const string invalidKey = "NonExistent_Log_Key";

            // Act
            var result = _resourceManager.LogMessageExists(invalidKey);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void ErrorMessageExists_WithInvalidKey_ShouldReturnFalse()
        {
            // Arrange
            const string invalidKey = "NonExistent_Error_Key";

            // Act
            var result = _resourceManager.ErrorMessageExists(invalidKey);

            // Assert
            result.Should().BeFalse();
        }

        [Fact]
        public void LogMessageExists_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            _resourceManager.Invoking(rm => rm.LogMessageExists(null!))
                .Should().Throw<ArgumentNullException>()
                .WithParameterName("key");
        }

        [Fact]
        public void ErrorMessageExists_WithNullKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            _resourceManager.Invoking(rm => rm.ErrorMessageExists(null!))
                .Should().Throw<ArgumentNullException>()
                .WithParameterName("key");
        }

        [Fact]
        public void GetLogMessage_WithSpecificCulture_ShouldUseProvidedCulture()
        {
            // Arrange
            const string key = "Connection_Established";
            var culture = CultureInfo.InvariantCulture;

            // Act
            var result = _resourceManager.GetLogMessage(key, culture);

            // Assert
            result.Should().NotBeNullOrEmpty();
            // Note: Since we only have default resources, this tests the culture parameter is accepted
        }

        [Fact]
        public void GetErrorMessage_WithSpecificCulture_ShouldUseProvidedCulture()
        {
            // Arrange
            const string key = "Validation_Required_Field";
            var culture = CultureInfo.InvariantCulture;

            // Act
            var result = _resourceManager.GetErrorMessage(key, culture);

            // Assert
            result.Should().NotBeNullOrEmpty();
            // Note: Since we only have default resources, this tests the culture parameter is accepted
        }

        [Fact]
        public void LogMessageExists_WithSpecificCulture_ShouldUseProvidedCulture()
        {
            // Arrange
            const string key = "Connection_Established";
            var culture = CultureInfo.InvariantCulture;

            // Act
            var result = _resourceManager.LogMessageExists(key, culture);

            // Assert
            result.Should().BeTrue();
        }

        [Fact]
        public void ErrorMessageExists_WithSpecificCulture_ShouldUseProvidedCulture()
        {
            // Arrange
            const string key = "Validation_Required_Field";
            var culture = CultureInfo.InvariantCulture;

            // Act
            var result = _resourceManager.ErrorMessageExists(key, culture);

            // Assert
            result.Should().BeTrue();
        }
    }
}