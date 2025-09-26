using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Middleware;
using S7.Services.Middleware;
using S7.Utils;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace S7.Core.Tests.Middleware
{
    /// <summary>
    /// Unit tests for ValidationPipeline class.
    /// </summary>
    public class ValidationPipelineTests
    {
        private readonly Mock<ILogger<ValidationPipeline>> _mockLogger;
        private readonly ValidationPipeline _validationPipeline;

        public ValidationPipelineTests()
        {
            _mockLogger = new Mock<ILogger<ValidationPipeline>>();
            _validationPipeline = new ValidationPipeline(_mockLogger.Object);
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new ValidationPipeline(null!));
        }

        [Fact]
        public async Task ExecuteAsync_WithNullOptions_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _validationPipeline.ExecuteAsync<TestCommandOptions>(null!, CancellationToken.None));
        }

        [Fact]
        public async Task ExecuteAsync_WithNoRegisteredMiddleware_ReturnsValidResult()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };

            // Act
            var result = await _validationPipeline.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.True(result.Value.IsValid);
            Assert.Empty(result.Value.Errors);
            Assert.Equal(0, result.Value.MiddlewareExecuted);
        }

        [Fact]
        public async Task ExecuteAsync_WithPassingMiddleware_ReturnsValidResult()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var mockMiddleware = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware.Setup(m => m.Order).Returns(10);
            mockMiddleware.Setup(m => m.StopOnFailure).Returns(false);
            mockMiddleware.Setup(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Success(true));

            _validationPipeline.RegisterMiddleware(mockMiddleware.Object);

            // Act
            var result = await _validationPipeline.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.True(result.Value.IsValid);
            Assert.Empty(result.Value.Errors);
            Assert.Equal(1, result.Value.MiddlewareExecuted);
            mockMiddleware.Verify(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ExecuteAsync_WithFailingMiddleware_ReturnsInvalidResult()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var mockMiddleware = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware.Setup(m => m.Order).Returns(10);
            mockMiddleware.Setup(m => m.StopOnFailure).Returns(true);
            mockMiddleware.Setup(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Failure("Validation failed"));

            _validationPipeline.RegisterMiddleware(mockMiddleware.Object);

            // Act
            var result = await _validationPipeline.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.False(result.Value.IsValid);
            Assert.Single(result.Value.Errors);
            Assert.Equal("Validation failed", result.Value.Errors[0].ErrorMessage);
            Assert.Equal(1, result.Value.MiddlewareExecuted);
        }

        [Fact]
        public async Task ExecuteAsync_WithMultipleMiddleware_ExecutesInOrder()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var executionOrder = new List<int>();

            var mockMiddleware1 = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware1.Setup(m => m.Order).Returns(20);
            mockMiddleware1.Setup(m => m.StopOnFailure).Returns(false);
            mockMiddleware1.Setup(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()))
                .Callback(() => executionOrder.Add(20))
                .ReturnsAsync(Result<bool>.Success(true));

            var mockMiddleware2 = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware2.Setup(m => m.Order).Returns(10);
            mockMiddleware2.Setup(m => m.StopOnFailure).Returns(false);
            mockMiddleware2.Setup(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()))
                .Callback(() => executionOrder.Add(10))
                .ReturnsAsync(Result<bool>.Success(true));

            _validationPipeline.RegisterMiddleware(mockMiddleware1.Object);
            _validationPipeline.RegisterMiddleware(mockMiddleware2.Object);

            // Act
            var result = await _validationPipeline.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.True(result.Value.IsValid);
            Assert.Equal(2, result.Value.MiddlewareExecuted);
            Assert.Equal(new[] { 10, 20 }, executionOrder); // Should execute in order
        }

        [Fact]
        public async Task ExecuteAsync_WithStopOnFailureMiddleware_StopsOnFailure()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };

            var mockMiddleware1 = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware1.Setup(m => m.Order).Returns(10);
            mockMiddleware1.Setup(m => m.StopOnFailure).Returns(true);
            mockMiddleware1.Setup(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<bool>.Failure("First middleware failed"));

            var mockMiddleware2 = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware2.Setup(m => m.Order).Returns(20);
            mockMiddleware2.Setup(m => m.StopOnFailure).Returns(false);

            _validationPipeline.RegisterMiddleware(mockMiddleware1.Object);
            _validationPipeline.RegisterMiddleware(mockMiddleware2.Object);

            // Act
            var result = await _validationPipeline.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.False(result.Value.IsValid);
            Assert.Single(result.Value.Errors);
            Assert.Equal(1, result.Value.MiddlewareExecuted); // Should stop after first middleware
            mockMiddleware2.Verify(m => m.ValidateAsync(It.IsAny<TestCommandOptions>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Fact]
        public async Task ExecuteAsync_WithCancellationToken_PropagatesCancellation()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var cts = new CancellationTokenSource();
            cts.Cancel();

            var mockMiddleware = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware.Setup(m => m.Order).Returns(10);
            mockMiddleware.Setup(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new OperationCanceledException());

            _validationPipeline.RegisterMiddleware(mockMiddleware.Object);

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() => 
                _validationPipeline.ExecuteAsync(options, cts.Token));
        }

        [Fact]
        public async Task ExecuteAsync_WithMiddlewareException_HandlesGracefully()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var mockMiddleware = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware.Setup(m => m.Order).Returns(10);
            mockMiddleware.Setup(m => m.StopOnFailure).Returns(false);
            mockMiddleware.Setup(m => m.ValidateAsync(options, It.IsAny<CancellationToken>()))
                .ThrowsAsync(new InvalidOperationException("Middleware error"));

            _validationPipeline.RegisterMiddleware(mockMiddleware.Object);

            // Act
            var result = await _validationPipeline.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.NotNull(result.Value);
            Assert.False(result.Value.IsValid);
            Assert.Single(result.Value.Errors);
            Assert.Contains("Validation middleware error", result.Value.Errors[0].ErrorMessage);
            Assert.Equal(ValidationSeverity.Critical, result.Value.Errors[0].Severity);
        }

        [Fact]
        public void RegisterMiddleware_WithNullMiddleware_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                _validationPipeline.RegisterMiddleware<TestCommandOptions>(null!));
        }

        [Fact]
        public void RegisterMiddleware_WithValidMiddleware_RegistersSuccessfully()
        {
            // Arrange
            var mockMiddleware = new Mock<IValidationMiddleware<TestCommandOptions>>();
            mockMiddleware.Setup(m => m.Order).Returns(10);

            // Act
            _validationPipeline.RegisterMiddleware(mockMiddleware.Object);

            // Assert
            Assert.Equal(1, _validationPipeline.GetMiddlewareCount<TestCommandOptions>());
        }

        [Fact]
        public void GetRegisteredMiddleware_ReturnsCorrectMiddleware()
        {
            // Arrange
            var mockMiddleware1 = new Mock<IValidationMiddleware<TestCommandOptions>>();
            var mockMiddleware2 = new Mock<IValidationMiddleware<MemoryDumpOptions>>();

            _validationPipeline.RegisterMiddleware(mockMiddleware1.Object);
            _validationPipeline.RegisterMiddleware(mockMiddleware2.Object);

            // Act
            var registeredMiddleware = _validationPipeline.GetRegisteredMiddleware();

            // Assert
            Assert.Equal(2, registeredMiddleware.Count);
            Assert.Contains(typeof(TestCommandOptions), registeredMiddleware.Keys);
            Assert.Contains(typeof(MemoryDumpOptions), registeredMiddleware.Keys);
        }

        [Fact]
        public void ClearMiddleware_RemovesAllMiddleware()
        {
            // Arrange
            var mockMiddleware = new Mock<IValidationMiddleware<TestCommandOptions>>();
            _validationPipeline.RegisterMiddleware(mockMiddleware.Object);
            Assert.Equal(1, _validationPipeline.GetMiddlewareCount<TestCommandOptions>());

            // Act
            _validationPipeline.ClearMiddleware<TestCommandOptions>();

            // Assert
            Assert.Equal(0, _validationPipeline.GetMiddlewareCount<TestCommandOptions>());
        }

        /// <summary>
        /// Test command options class for testing purposes.
        /// </summary>
        private class TestCommandOptions : CommandHandlerOptions
        {
            public TestCommandOptions()
            {
                CorrelationId = Guid.NewGuid().ToString();
                TimeoutMs = 30000;
            }
        }
    }
}