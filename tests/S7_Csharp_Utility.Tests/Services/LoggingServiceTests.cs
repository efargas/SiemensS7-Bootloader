using System;
using System.Linq;
using Avalonia.Threading;
using FluentAssertions;
using S7_Csharp_Utility.Services;
using Xunit;

namespace S7_Csharp_Utility.Tests.Services
{
    /// <summary>
    /// Unit tests for LoggingService with ResourceManagerService integration.
    /// </summary>
    public class LoggingServiceTests
    {
        private readonly ResourceManagerService _resourceManager;
        private readonly LoggingService _loggingService;

        public LoggingServiceTests()
        {
            // Create a real ResourceManagerService for testing
            _resourceManager = new ResourceManagerService();
            
            // Create LoggingService with real resource manager
            // Note: Using Dispatcher.UIThread for testing, in real scenarios this would be injected
            _loggingService = new LoggingService(Dispatcher.UIThread, _resourceManager);
        }

        [Fact]
        public void Constructor_WithResourceManager_ShouldInitializeSuccessfully()
        {
            // Act & Assert
            _loggingService.Should().NotBeNull();
            _loggingService.LogMessages.Should().NotBeNull();
            _loggingService.LogMessages.Should().BeEmpty();
        }

        [Fact]
        public void Constructor_WithoutResourceManager_ShouldInitializeSuccessfully()
        {
            // Act
            var service = new LoggingService(Dispatcher.UIThread);

            // Assert
            service.Should().NotBeNull();
            service.LogMessages.Should().NotBeNull();
            service.LogMessages.Should().BeEmpty();
        }

        [Fact]
        public void Log_WithMessage_ShouldAddToLogMessages()
        {
            // Arrange
            const string message = "Test log message";
            const LogCategory category = LogCategory.Info;

            // Act
            _loggingService.Log(message, category);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().HaveCount(1);
            var logEntry = _loggingService.LogMessages.First();
            logEntry.Message.Should().Be(message);
            logEntry.Category.Should().Be(category);
            logEntry.Timestamp.Should().BeCloseTo(DateTime.Now, TimeSpan.FromSeconds(1));
        }

        [Fact]
        public void LogWithKey_WithResourceManager_ShouldUseResourceMessage()
        {
            // Arrange
            const string resourceKey = "Connection_Established";
            const string plcAddress = "192.168.1.100";

            // Act
            _loggingService.LogWithKey(resourceKey, LogCategory.Info, plcAddress);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().HaveCount(1);
            var logEntry = _loggingService.LogMessages.First();
            logEntry.Category.Should().Be(LogCategory.Info);
            logEntry.Message.Should().Contain(plcAddress);
            logEntry.Message.Should().NotBe(resourceKey); // Should be formatted, not just the key
        }

        [Fact]
        public void LogWithKey_WithoutResourceManager_ShouldUseFallback()
        {
            // Arrange
            var serviceWithoutResourceManager = new LoggingService(Dispatcher.UIThread);
            const string resourceKey = "Connection_Established";
            const string arg1 = "192.168.1.100";

            // Act
            serviceWithoutResourceManager.LogWithKey(resourceKey, LogCategory.Info, arg1);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            serviceWithoutResourceManager.LogMessages.Should().HaveCount(1);
            var logMessage = serviceWithoutResourceManager.LogMessages.First().Message;
            logMessage.Should().Contain(resourceKey);
            logMessage.Should().Contain(arg1);
        }

        [Fact]
        public void LogError_WithResourceManager_ShouldUseErrorMessage()
        {
            // Arrange
            const string resourceKey = "Connection_Failed";
            const string plcAddress = "192.168.1.100";
            const string errorDetails = "Connection refused";

            // Act
            _loggingService.LogError(resourceKey, plcAddress, errorDetails);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().HaveCount(1);
            var logEntry = _loggingService.LogMessages.First();
            logEntry.Category.Should().Be(LogCategory.Error);
            logEntry.Message.Should().Contain(plcAddress);
            logEntry.Message.Should().Contain(errorDetails);
            logEntry.Message.Should().NotBe(resourceKey); // Should be formatted, not just the key
        }

        [Fact]
        public void LogError_WithoutResourceManager_ShouldUseFallback()
        {
            // Arrange
            var serviceWithoutResourceManager = new LoggingService(Dispatcher.UIThread);
            const string resourceKey = "Connection_Failed";
            const string arg1 = "192.168.1.100";
            const string arg2 = "Connection refused";

            // Act
            serviceWithoutResourceManager.LogError(resourceKey, arg1, arg2);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            serviceWithoutResourceManager.LogMessages.Should().HaveCount(1);
            var logEntry = serviceWithoutResourceManager.LogMessages.First();
            logEntry.Category.Should().Be(LogCategory.Error);
            logEntry.Message.Should().Contain(resourceKey);
            logEntry.Message.Should().Contain(arg1);
            logEntry.Message.Should().Contain(arg2);
        }

        [Fact]
        public void LogWithKey_WithEmptyKey_ShouldNotLog()
        {
            // Act
            _loggingService.LogWithKey("", LogCategory.Info);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().BeEmpty();
        }

        [Fact]
        public void LogWithKey_WithNullKey_ShouldNotLog()
        {
            // Act
            _loggingService.LogWithKey(null!, LogCategory.Info);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().BeEmpty();
        }

        [Fact]
        public void LogError_WithEmptyKey_ShouldNotLog()
        {
            // Act
            _loggingService.LogError("", Array.Empty<object>());

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().BeEmpty();
        }

        [Fact]
        public void LogError_WithNullKey_ShouldNotLog()
        {
            // Act
            _loggingService.LogError(null!, Array.Empty<object>());

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().BeEmpty();
        }

        [Fact]
        public void LogWithKey_WithoutArgs_ShouldUseUnformattedMessage()
        {
            // Arrange
            const string resourceKey = "Application_Starting";

            // Act
            _loggingService.LogWithKey(resourceKey, LogCategory.Info);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().HaveCount(1);
            var logEntry = _loggingService.LogMessages.First();
            logEntry.Category.Should().Be(LogCategory.Info);
            logEntry.Message.Should().NotBe(resourceKey); // Should be the actual message, not the key
        }

        [Fact]
        public void LogError_WithoutArgs_ShouldUseUnformattedMessage()
        {
            // Arrange
            const string resourceKey = "Configuration_Invalid";

            // Act
            _loggingService.LogError(resourceKey);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().HaveCount(1);
            var logEntry = _loggingService.LogMessages.First();
            logEntry.Category.Should().Be(LogCategory.Error);
            logEntry.Message.Should().NotBe(resourceKey); // Should be the actual message, not the key
        }

        [Fact]
        public void Clear_ShouldRemoveAllLogMessages()
        {
            // Arrange
            _loggingService.Log("Test message 1", LogCategory.Info);
            _loggingService.Log("Test message 2", LogCategory.Warning);
            System.Threading.Thread.Sleep(100); // Wait for messages to be added

            // Act
            _loggingService.Clear();
            System.Threading.Thread.Sleep(100); // Wait for clear to process

            // Assert
            _loggingService.LogMessages.Should().BeEmpty();
        }

        [Theory]
        [InlineData(LogCategory.Info)]
        [InlineData(LogCategory.Warning)]
        [InlineData(LogCategory.Error)]
        [InlineData(LogCategory.Debug)]
        public void Log_WithDifferentCategories_ShouldSetCorrectCategory(LogCategory category)
        {
            // Arrange
            const string message = "Test message";

            // Act
            _loggingService.Log(message, category);

            // Wait for dispatcher to process
            System.Threading.Thread.Sleep(100);

            // Assert
            _loggingService.LogMessages.Should().HaveCount(1);
            _loggingService.LogMessages.First().Category.Should().Be(category);
        }

        [Fact]
        public void FilterInfo_WhenChanged_ShouldTriggerPropertyChanged()
        {
            // Arrange
            var propertyChangedTriggered = false;
            _loggingService.PropertyChanged += (sender, args) =>
            {
                if (args.PropertyName == nameof(LoggingService.FilterInfo))
                    propertyChangedTriggered = true;
            };

            // Act
            _loggingService.FilterInfo = false;

            // Assert
            propertyChangedTriggered.Should().BeTrue();
        }

        [Fact]
        public void FilterError_WhenChanged_ShouldTriggerPropertyChanged()
        {
            // Arrange
            var propertyChangedTriggered = false;
            _loggingService.PropertyChanged += (sender, args) =>
            {
                if (args.PropertyName == nameof(LoggingService.FilterError))
                    propertyChangedTriggered = true;
            };

            // Act
            _loggingService.FilterError = false;

            // Assert
            propertyChangedTriggered.Should().BeTrue();
        }

        [Fact]
        public void FilterDebug_WhenChanged_ShouldTriggerPropertyChanged()
        {
            // Arrange
            var propertyChangedTriggered = false;
            _loggingService.PropertyChanged += (sender, args) =>
            {
                if (args.PropertyName == nameof(LoggingService.FilterDebug))
                    propertyChangedTriggered = true;
            };

            // Act
            _loggingService.FilterDebug = false;

            // Assert
            propertyChangedTriggered.Should().BeTrue();
        }
    }
}