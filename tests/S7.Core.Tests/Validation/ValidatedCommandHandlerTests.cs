using Microsoft.Extensions.Logging;
using Moq;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Middleware;
using S7.Core.Abstractions.Validation;
using S7.Utils;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace S7.Core.Tests.Validation
{
    public class ValidatedCommandHandlerTests
    {
        private readonly Mock<ILogger<TestValidatedCommandHandler>> _mockLogger;
        private readonly Mock<IValidationPipeline> _mockValidationPipeline;
        private readonly Mock<IValidator<TestCommandOptions>> _mockValidator;

        public ValidatedCommandHandlerTests()
        {
            _mockLogger = new Mock<ILogger<TestValidatedCommandHandler>>();
            _mockValidationPipeline = new Mock<IValidationPipeline>();
            _mockValidator = new Mock<IValidator<TestCommandOptions>>();
        }

        [Fact]
        public async Task ExecuteAsync_WithValidationPipelineSuccess_ExecutesCommand()
        {
            // Arrange
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, _mockValidationPipeline.Object, _mockValidator.Object);
            var options = new TestCommandOptions();
            var pipelineResult = new ValidationPipelineResult { IsValid = true };
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("Test Result", result.Data);
            _mockValidationPipeline.Verify(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Fact]
        public async Task ExecuteAsync_WithValidationPipelineFailure_ReturnsValidationFailure()
        {
            // Arrange
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, _mockValidationPipeline.Object, _mockValidator.Object);
            var options = new TestCommandOptions();
            var pipelineResult = new ValidationPipelineResult
            {
                IsValid = false,
                Errors = new List<ValidationError> { new ValidationError { ErrorMessage = "Pipeline error" } }
            };
            _mockValidationPipeline
                .Setup(vp => vp.ExecuteAsync(options, It.IsAny<CancellationToken>()))
                .ReturnsAsync(Result<ValidationPipelineResult>.Success(pipelineResult));

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.False(result.IsSuccess);
            Assert.Contains("Pipeline error", result.ErrorMessage);
        }

        [Fact]
        public async Task ExecuteAsync_WithoutValidationPipeline_FallsBackToLegacyValidation()
        {
            // Arrange
            var handler = new TestValidatedCommandHandler(_mockLogger.Object, null, _mockValidator.Object);
            var options = new TestCommandOptions();
            _mockValidator.Setup(v => v.Validate(options)).Returns(ValidationResultInfo.Success());

            // Act
            var result = await handler.ExecuteAsync(options, CancellationToken.None);

            // Assert
            Assert.True(result.IsSuccess);
            Assert.Equal("Test Result", result.Data);
            _mockValidator.Verify(v => v.Validate(options), Times.Once);
        }

        private class TestCommandOptions : CommandHandlerOptions { }

        private class TestValidatedCommandHandler : ValidatedCommandHandler<TestCommandOptions, string>
        {
            public TestValidatedCommandHandler(
                ILogger<TestValidatedCommandHandler> logger,
                IValidationPipeline? validationPipeline,
                IValidator<TestCommandOptions>? validator)
                : base(logger, validationPipeline, validator) { }

            protected override Task<string> ExecuteInternalAsync(TestCommandOptions options, CancellationToken cancellationToken = default)
            {
                return Task.FromResult("Test Result");
            }
        }
    }
}