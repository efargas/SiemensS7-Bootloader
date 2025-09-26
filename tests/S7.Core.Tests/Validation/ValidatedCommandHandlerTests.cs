using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Middleware;
using S7.Core.Abstractions.Validation;
using S7.Utils;
using System;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace S7.Core.Tests.Validation
{
    /// <summary>
    /// Unit tests for ValidatedCommandHandler class.
    /// </summary>
    public class ValidatedCommandHandlerTests
    {
        private readonly Mock<ILogger<TestValidatedCommandHandler>> _mockLogger;
        private readonly Mock<IValidationPipeline> _mockValidationPipeline;
        private readonly Mock<IValidator<TestCommandOptions>> _mockValidator;
        private readonly TestValidatedCommandHandler _commandHandler;

        public ValidatedCommandHandlerTests()
        {
            _mockLogger = new Mock<ILogger<TestValidatedCommandHandler>>();
            _mockValidationPipeline = new Mock<IValidationPipeline>();
            _mockValidator = new Mock<IValidator<TestCommandOptions>>();
            _commandHandler = new TestValidatedCommandHandler(_mockLogger.Object, _mockValidationPipeline.Object, _mockValidator.Object);
        }

        #region Constructor Tests

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new TestValidatedCommandHandler(null!, _mockValidationPipeline.Object, _mockValidator.Object));
        }

        [Fact]
        public void Constructor_WithNullValidationPipeline_DoesNotThrow()
        {
            // Act & Assert - Should not throw, validation pipeline is optional
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, null, _mockValidator.Object);
            Assert.NotNull(handler);
        }

        [Fact]
        public void Constructor_WithNullValidator_DoesNotThrow()
        {
            // Act & Assert - Should not throw, validator is optional
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, _mockValidationPipeline.Object, null);
            Assert.NotNull(handler);
        }

        #endregion

        #region ExecuteAsync Tests

        [Fact]
        public async Task ExecuteAsync_WithNullOptions_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _commandHandler.ExecuteAsync<string>(null!, CancellationToken.None));
        }

        [Fact]
        public async Task ExecuteAsync_WithValidationPipelineSuccess_ExecutesCommand()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var pipelineResult = new ValidationPipelineResult { IsValid = true };
            
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            // Act
            var result = await _commandHandler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("Test Result", result.Value);
            _mockValidationPipeline.Verify(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ExecuteAsync_WithValidationPipelineFailure_ReturnsValidationFailure()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var pipelineResult = new ValidationPipelineResult 
            { 
                IsValid = false,
                Errors = new List<ValidationError>
                {
                    new ValidationError { ErrorMessage = "Test validation error", PropertyName = "TestProperty" }
                }
            };
            
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            // Act
            var result = await _commandHandler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Test validation error", result.ErrorMessage);
            Assert.Equal(CommandResultType.ValidationFailure, result.ResultType);
        }

        [Fact]
        public async Task ExecuteAsync_WithValidationPipelineException_ReturnsFailure()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Failure("Pipeline execution failed"));

            // Act
            var result = await _commandHandler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Pipeline execution failed", result.ErrorMessage);
        }

        [Fact]
        public async Task ExecuteAsync_WithoutValidationPipeline_FallsBackToLegacyValidation()
        {
            // Arrange
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, null, _mockValidator.Object);
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            
            _mockValidator
                .Setup(v => v.Validate(options))
                .Returns(ValidationResult.Success());

            // Act
            var result = await handler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("Test Result", result.Value);
            _mockValidator.Verify(v => v.Validate(options), Times.Once);
        }

        [Fact]
        public async Task ExecuteAsync_WithLegacyValidationFailure_ReturnsValidationFailure()
        {
            // Arrange
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, null, _mockValidator.Object);
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            
            _mockValidator
                .Setup(v => v.Validate(options))
                .Returns(ValidationResult.Failure(new[] { "Legacy validation error" }));

            // Act
            var result = await handler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Legacy validation error", result.ErrorMessage);
            Assert.Equal(CommandResultType.ValidationFailure, result.ResultType);
        }

        [Fact]
        public async Task ExecuteAsync_WithBuiltInValidationFailure_ReturnsValidationFailure()
        {
            // Arrange
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, null, null);
            var options = new TestCommandOptions 
            { 
                CorrelationId = "", // Invalid - empty correlation ID
                TimeoutMs = 30000
            };

            // Act
            var result = await handler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Equal(CommandResultType.ValidationFailure, result.ResultType);
        }

        [Fact]
        public async Task ExecuteAsync_WithRetryPolicy_RetriesOnFailure()
        {
            // Arrange
            var options = new TestCommandOptions 
            { 
                CorrelationId = "test-123",
                RetryPolicy = new RetryPolicy
                {
                    MaxRetries = 2,
                    RetryDelayMs = 100,
                    RetryableExceptions = new[] { typeof(InvalidOperationException) }
                }
            };
            var pipelineResult = new ValidationPipelineResult { IsValid = true };
            
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            var handler = new TestValidatedCommandHandlerWithRetry(_mockLogger.Object, _mockValidationPipeline.Object, _mockValidator.Object);

            // Act
            var result = await handler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("Test Result", result.Value);
        }

        [Fact]
        public async Task ExecuteAsync_WithTimeout_ReturnsTimeoutFailure()
        {
            // Arrange
            var options = new TestCommandOptions 
            { 
                CorrelationId = "test-123",
                TimeoutMs = 100 // Very short timeout
            };
            var pipelineResult = new ValidationPipelineResult { IsValid = true };
            
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            var handler = new TestValidatedCommandHandlerWithDelay(_mockLogger.Object, _mockValidationPipeline.Object, _mockValidator.Object);

            // Act
            var result = await handler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("timed out", result.ErrorMessage);
        }

        [Fact]
        public async Task ExecuteAsync_WithCancellation_ReturnsCancellationFailure()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var cts = new CancellationTokenSource();
            cts.Cancel();

            // Act
            var result = await _commandHandler.ExecuteAsync<string>(options, cts.Token);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("cancelled", result.ErrorMessage);
        }

        [Fact]
        public async Task ExecuteAsync_WithCommandException_ReturnsExceptionFailure()
        {
            // Arrange
            var options = new TestCommandOptions { CorrelationId = "test-123" };
            var pipelineResult = new ValidationPipelineResult { IsValid = true };
            
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            var handler = new TestValidatedCommandHandlerWithException(_mockLogger.Object, _mockValidationPipeline.Object, _mockValidator.Object);

            // Act
            var result = await handler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Test exception", result.ErrorMessage);
            Assert.Equal(CommandResultType.Exception, result.ResultType);
        }

        #endregion

        #region Logging Tests

        [Fact]
        public async Task ExecuteAsync_WithDetailedLogging_LogsExecutionDetails()
        {
            // Arrange
            var options = new TestCommandOptions 
            { 
                CorrelationId = "test-123",
                EnableDetailedLogging = true
            };
            var pipelineResult = new ValidationPipelineResult { IsValid = true };
            
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            // Act
            var result = await _commandHandler.ExecuteAsync<string>(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            
            // Verify logging calls
            _mockLogger.Verify(
                x => x.Log(
                    LogLevel.Information,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Starting validated command execution")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception, string>>()),
                Times.Once);

            _mockLogger.Verify(
                x => x.Log(
                    LogLevel.Information,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("completed successfully")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception, string>>()),
                Times.Once);
        }

        #endregion

        #region Test Helper Classes

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

        /// <summary>
        /// Test validated command handler for testing purposes.
        /// </summary>
        private class TestValidatedCommandHandler : ValidatedCommandHandler<TestCommandOptions>
        {
            public TestValidatedCommandHandler(ILogger logger, IValidationPipeline? validationPipeline = null, IValidator<TestCommandOptions>? validator = null)
                : base(logger, validationPipeline, validator)
            {
            }

            protected override Task<TResult> ExecuteInternalAsync<TResult>(TestCommandOptions options, CancellationToken cancellationToken = default)
            {
                return Task.FromResult((TResult)(object)"Test Result");
            }
        }

        /// <summary>
        /// Test validated command handler that simulates retry behavior.
        /// </summary>
        private class TestValidatedCommandHandlerWithRetry : ValidatedCommandHandler<TestCommandOptions>
        {
            private int _attemptCount = 0;

            public TestValidatedCommandHandlerWithRetry(ILogger logger, IValidationPipeline? validationPipeline = null, IValidator<TestCommandOptions>? validator = null)
                : base(logger, validationPipeline, validator)
            {
            }

            protected override Task<TResult> ExecuteInternalAsync<TResult>(TestCommandOptions options, CancellationToken cancellationToken = default)
            {
                _attemptCount++;
                if (_attemptCount < 3)
                {
                    throw new InvalidOperationException("Simulated failure for retry testing");
                }
                return Task.FromResult((TResult)(object)"Test Result");
            }
        }

        /// <summary>
        /// Test validated command handler that simulates delay for timeout testing.
        /// </summary>
        private class TestValidatedCommandHandlerWithDelay : ValidatedCommandHandler<TestCommandOptions>
        {
            public TestValidatedCommandHandlerWithDelay(ILogger logger, IValidationPipeline? validationPipeline = null, IValidator<TestCommandOptions>? validator = null)
                : base(logger, validationPipeline, validator)
            {
            }

            protected override async Task<TResult> ExecuteInternalAsync<TResult>(TestCommandOptions options, CancellationToken cancellationToken = default)
            {
                await Task.Delay(200, cancellationToken); // Delay longer than timeout
                return (TResult)(object)"Test Result";
            }
        }

        /// <summary>
        /// Test validated command handler that throws an exception.
        /// </summary>
        private class TestValidatedCommandHandlerWithException : ValidatedCommandHandler<TestCommandOptions>
        {
            public TestValidatedCommandHandlerWithException(ILogger logger, IValidationPipeline? validationPipeline = null, IValidator<TestCommandOptions>? validator = null)
                : base(logger, validationPipeline, validator)
            {
            }

            protected override Task<TResult> ExecuteInternalAsync<TResult>(TestCommandOptions options, CancellationToken cancellationToken = default)
            {
                throw new InvalidOperationException("Test exception");
            }
        }

        #endregion
    }
}