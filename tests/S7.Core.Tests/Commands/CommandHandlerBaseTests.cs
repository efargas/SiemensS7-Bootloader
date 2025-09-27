using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Validation;
using Xunit;

namespace S7.Core.Tests.Commands
{
    public class CommandHandlerBaseTests
    {
        private readonly Mock<ILogger<TestCommandHandler>> _mockLogger;
        private readonly Mock<IValidator<TestCommandOptions>> _mockValidator;

        public CommandHandlerBaseTests()
        {
            _mockLogger = new Mock<ILogger<TestCommandHandler>>();
            _mockValidator = new Mock<IValidator<TestCommandOptions>>();
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new TestCommandHandler(null!, null));
        }

        [Fact]
        public void Constructor_WithValidParameters_InitializesCorrectly()
        {
            // Act
            var handler = new TestCommandHandler(_mockLogger.Object, _mockValidator.Object);

            // Assert
            Assert.NotNull(handler);
            Assert.Equal(_mockLogger.Object, handler.Logger);
            Assert.Equal(_mockValidator.Object, handler.Validator);
        }

        [Fact]
        public void Constructor_WithNullValidator_InitializesCorrectly()
        {
            // Act
            var handler = new TestCommandHandler(_mockLogger.Object, null);

            // Assert
            Assert.NotNull(handler);
            Assert.Equal(_mockLogger.Object, handler.Logger);
            Assert.Null(handler.Validator);
        }

        [Fact]
        public async Task ExecuteAsync_WithNullOptions_ThrowsArgumentNullException()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                handler.ExecuteAsync(null!, CancellationToken.None));
        }

        [Fact]
        public async Task ExecuteAsync_WithValidOptions_ReturnsSuccessResult()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions();
            handler.SetExecuteResult("test-result");

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("test-result", result.Data);
            Assert.Equal(options.CorrelationId, result.CorrelationId);
        }

        [Fact]
        public async Task ExecuteAsync_WithValidationFailure_ReturnsValidationFailureResult()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions();
            handler.SetValidationResult(ValidationResultInfo.Failure("Validation error"));

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Validation error", result.ErrorMessage);
            Assert.Equal(options.CorrelationId, result.CorrelationId);
        }

        [Fact]
        public async Task ExecuteAsync_WithExternalValidatorFailure_ReturnsValidationFailureResult()
        {
            // Arrange
            var validationResult = ValidationResultInfo.Failure("External validation error");
            _mockValidator.Setup(v => v.Validate(It.IsAny<TestCommandOptions>()))
                         .Returns(validationResult);

            var handler = new TestCommandHandler(_mockLogger.Object, _mockValidator.Object);
            var options = new TestCommandOptions();

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("External validation error", result.ErrorMessage);
            _mockValidator.Verify(v => v.Validate(options), Times.Once);
        }

        [Fact]
        public async Task ExecuteAsync_WithBuiltInValidationFailure_ReturnsValidationFailureResult()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions();
            options.SetBuiltInValidationErrors(new[] { new System.ComponentModel.DataAnnotations.ValidationResult("Built-in validation error") });

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Built-in validation error", result.ErrorMessage);
        }

        [Fact]
        public async Task ExecuteAsync_WithException_ReturnsFailureResult()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions();
            handler.SetExecuteException(new InvalidOperationException("Test exception"));

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Test exception", result.ErrorMessage);
            Assert.Equal(options.CorrelationId, result.CorrelationId);
        }

        [Fact]
        public async Task ExecuteAsync_WithCancellation_ReturnsCancellationResult()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions();
            var cts = new CancellationTokenSource();

            handler.SetExecuteDelay(TimeSpan.FromMilliseconds(500));
            cts.CancelAfter(TimeSpan.FromMilliseconds(100));

            // Act
            var result = await handler.ExecuteAsync(options, cts.Token);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("cancelled", result.ErrorMessage);
        }

        [Fact]
        public async Task ExecuteAsync_WithTimeout_ReturnsTimeoutResult()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions { TimeoutMs = 1000 }; // Use minimum valid timeout
            handler.SetExecuteDelay(TimeSpan.FromMilliseconds(2000)); // Longer than timeout

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("timed out", result.ErrorMessage);
        }

        [Fact]
        public async Task ExecuteAsync_WithRetryPolicy_RetriesOnFailure()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions
            {
                RetryPolicy = new RetryPolicy
                {
                    MaxRetries = 2,
                    RetryDelayMs = 10,
                    UseExponentialBackoff = false,
                    RetryableExceptions = new[] { typeof(InvalidOperationException) }
                }
            };

            // Set up to fail twice, then succeed
            handler.SetExecuteExceptions(new[]
            {
                new InvalidOperationException("First failure"),
                new InvalidOperationException("Second failure")
            });
            handler.SetExecuteResult("success-after-retries");

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("success-after-retries", result.Data);
            Assert.Equal(3, handler.ExecuteCallCount); // Initial + 2 retries
        }

        [Fact]
        public async Task ExecuteAsync_WithRetryPolicyExhausted_ReturnsFailureResult()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions
            {
                RetryPolicy = new RetryPolicy
                {
                    MaxRetries = 1,
                    RetryDelayMs = 10,
                    UseExponentialBackoff = false,
                    RetryableExceptions = new[] { typeof(InvalidOperationException) }
                }
            };

            handler.SetExecuteException(new InvalidOperationException("Persistent failure"));

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Persistent failure", result.ErrorMessage);
            Assert.Equal(2, handler.ExecuteCallCount); // Initial + 1 retry
        }

        [Fact]
        public async Task ExecuteAsync_WithNonRetryableException_DoesNotRetry()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions
            {
                RetryPolicy = new RetryPolicy
                {
                    MaxRetries = 2,
                    RetryDelayMs = 10,
                    UseExponentialBackoff = false,
                    RetryableExceptions = new[] { typeof(InvalidOperationException) }
                }
            };

            handler.SetExecuteException(new ArgumentException("Non-retryable exception"));

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Non-retryable exception", result.ErrorMessage);
            Assert.Equal(1, handler.ExecuteCallCount); // No retries
        }

        [Fact]
        public async Task ExecuteAsync_WithExponentialBackoff_UsesCorrectDelays()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions
            {
                RetryPolicy = new RetryPolicy
                {
                    MaxRetries = 2,
                    RetryDelayMs = 100,
                    UseExponentialBackoff = true,
                    RetryableExceptions = new[] { typeof(InvalidOperationException) }
                }
            };

            handler.SetExecuteException(new InvalidOperationException("Test failure"));

            var startTime = DateTime.UtcNow;

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            var totalTime = DateTime.UtcNow - startTime;
            // With exponential backoff: 100ms + 200ms = 300ms minimum
            Assert.True(totalTime.TotalMilliseconds >= 250); // Allow some tolerance
            Assert.False(result.IsSuccess);
        }

        [Fact]
        public async Task ExecuteAsync_WithDetailedLogging_LogsCorrectly()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions { EnableDetailedLogging = true };
            handler.SetExecuteResult("test-result");

            // Act
            await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            _mockLogger.Verify(
                x => x.Log(
                    LogLevel.Information,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Starting command execution")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
                Times.Once);

            _mockLogger.Verify(
                x => x.Log(
                    LogLevel.Information,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Command execution completed successfully")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
                Times.Once);
        }

        [Fact]
        public async Task ExecuteAsync_WithCustomValidation_CallsCustomValidationMethod()
        {
            // Arrange
            var handler = new TestCommandHandler(_mockLogger.Object, null);
            var options = new TestCommandOptions();
            handler.SetCustomValidationResult(ValidationResultInfo.Failure("Custom validation error"));

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Custom validation error", result.ErrorMessage);
            Assert.True(handler.CustomValidationCalled);
        }

        // Test command handler implementation for testing
        public class TestCommandHandler : CommandHandler<TestCommandOptions, string>
        {
            private string? _executeResult;
            private Exception? _executeException;
            private Queue<Exception>? _executeExceptions;
            private TimeSpan _executeDelay = TimeSpan.Zero;
            private ValidationResultInfo? _validationResult;
            private ValidationResultInfo? _customValidationResult;

            public int ExecuteCallCount { get; private set; }
            public bool CustomValidationCalled { get; private set; }

            public new ILogger Logger => base.Logger;
            public new IValidator<TestCommandOptions>? Validator => base.Validator;

            public TestCommandHandler(ILogger<TestCommandHandler> logger, IValidator<TestCommandOptions>? validator = null)
                : base(logger, validator)
            {
            }

            public void SetExecuteResult(string result)
            {
                _executeResult = result;
                _executeException = null;
                // Don't clear _executeExceptions to allow for retry scenarios
            }

            public void SetExecuteException(Exception exception)
            {
                _executeException = exception;
                _executeResult = null;
                _executeExceptions = null;
            }

            public void SetExecuteExceptions(Exception[] exceptions)
            {
                _executeExceptions = new Queue<Exception>(exceptions);
                _executeException = null;
                // Don't clear _executeResult to allow for success after retries
            }

            public void SetExecuteDelay(TimeSpan delay)
            {
                _executeDelay = delay;
            }

            public void SetValidationResult(ValidationResultInfo result)
            {
                _validationResult = result;
            }

            public void SetCustomValidationResult(ValidationResultInfo result)
            {
                _customValidationResult = result;
            }

            protected override async Task<string> ExecuteInternalAsync(
                TestCommandOptions options,
                CancellationToken cancellationToken = default)
            {
                ExecuteCallCount++;

                if (_executeDelay > TimeSpan.Zero)
                {
                    await Task.Delay(_executeDelay, cancellationToken).ConfigureAwait(false);
                }

                // Handle queued exceptions first
                if (_executeExceptions?.Count > 0)
                {
                    throw _executeExceptions.Dequeue();
                }

                // Handle single exception
                if (_executeException != null)
                {
                    throw _executeException;
                }

                // Return result (success case)
                return _executeResult ?? "default-result";
            }

            protected override async Task<ValidationResultInfo> ValidateOptionsAsync(
                TestCommandOptions options,
                CancellationToken cancellationToken = default)
            {
                if (_validationResult != null)
                {
                    return _validationResult;
                }

                return await base.ValidateOptionsAsync(options, cancellationToken).ConfigureAwait(false);
            }

            protected override Task<ValidationResultInfo> ValidateOptionsInternalAsync(
                TestCommandOptions options,
                CancellationToken cancellationToken = default)
            {
                CustomValidationCalled = true;

                if (_customValidationResult != null)
                {
                    return Task.FromResult(_customValidationResult);
                }

                return base.ValidateOptionsInternalAsync(options, cancellationToken);
            }
        }

        // Test command options for testing
        public class TestCommandOptions : CommandHandlerOptions
        {
            private IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult>? _builtInValidationErrors;

            public void SetBuiltInValidationErrors(IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> errors)
            {
                _builtInValidationErrors = errors;
            }

            public override IEnumerable<System.ComponentModel.DataAnnotations.ValidationResult> Validate()
            {
                if (_builtInValidationErrors != null)
                {
                    return _builtInValidationErrors;
                }

                return base.Validate();
            }
        }
    }
}