using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Commands;
using S7.Services.Middleware;
using System;
using System.ComponentModel.DataAnnotations;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace S7.Core.Tests.Middleware
{
    /// <summary>
    /// Unit tests for DataAnnotationsValidationMiddleware class.
    /// </summary>
    public class DataAnnotationsValidationMiddlewareTests
    {
        private readonly Mock<ILogger<DataAnnotationsValidationMiddleware<TestCommandOptions>>> _mockLogger;
        private readonly DataAnnotationsValidationMiddleware<TestCommandOptions> _middleware;

        public DataAnnotationsValidationMiddlewareTests()
        {
            _mockLogger = new Mock<ILogger<DataAnnotationsValidationMiddleware<TestCommandOptions>>>();
            _middleware = new DataAnnotationsValidationMiddleware<TestCommandOptions>(_mockLogger.Object);
        }

        [Fact]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new DataAnnotationsValidationMiddleware<TestCommandOptions>(null!));
        }

        [Fact]
        public void Order_ReturnsCorrectValue()
        {
            // Assert
            Assert.Equal(10, _middleware.Order);
        }

        [Fact]
        public void StopOnFailure_ReturnsTrue()
        {
            // Assert
            Assert.True(_middleware.StopOnFailure);
        }

        [Fact]
        public async Task ValidateAsync_WithNullOptions_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _middleware.ValidateAsync(null!, CancellationToken.None));
        }

        [Fact]
        public async Task ValidateAsync_WithValidOptions_ReturnsSuccess()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RequiredProperty = "Valid Value"
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        [Fact]
        public async Task ValidateAsync_WithInvalidOptions_ReturnsFailure()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RequiredProperty = null // This should fail validation
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("RequiredProperty is required", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithMultipleValidationErrors_ReturnsAggregatedErrors()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RequiredProperty = null, // Required validation failure
                RangeProperty = 150 // Range validation failure (max 100)
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("RequiredProperty is required", result.Error.Message);
            Assert.Contains("RangeProperty must be between 1 and 100", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithStringLengthValidation_ValidatesCorrectly()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RequiredProperty = "Valid",
                StringLengthProperty = "This string is way too long for the validation attribute" // Exceeds max length
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("StringLengthProperty cannot exceed 20 characters", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithRegexValidation_ValidatesCorrectly()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RequiredProperty = "Valid",
                EmailProperty = "invalid-email" // Invalid email format
            };

            // Act
            var result = await _middleware.ValidateAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("EmailProperty must be a valid email address", result.Error.Message);
        }

        [Fact]
        public async Task ValidateAsync_WithCancellationToken_CompletesSuccessfully()
        {
            // Arrange
            var options = new TestCommandOptions
            {
                CorrelationId = "test-123",
                TimeoutMs = 30000,
                RequiredProperty = "Valid Value"
            };
            var cts = new CancellationTokenSource();

            // Act
            var result = await _middleware.ValidateAsync(options, cts.Token);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.True(result.Value);
        }

        /// <summary>
        /// Test command options class with validation attributes for testing purposes.
        /// </summary>
        private class TestCommandOptions : CommandHandlerOptions
        {
            public TestCommandOptions()
            {
                CorrelationId = Guid.NewGuid().ToString();
                TimeoutMs = 30000;
            }

            [Required(ErrorMessage = "RequiredProperty is required")]
            public string? RequiredProperty { get; set; }

            [Range(1, 100, ErrorMessage = "RangeProperty must be between 1 and 100")]
            public int RangeProperty { get; set; } = 50;

            [StringLength(20, ErrorMessage = "StringLengthProperty cannot exceed 20 characters")]
            public string? StringLengthProperty { get; set; }

            [RegularExpression(@"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", 
                ErrorMessage = "EmailProperty must be a valid email address")]
            public string? EmailProperty { get; set; }
        }
    }
}