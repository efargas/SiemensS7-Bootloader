using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Middleware;
using S7.Core.Abstractions.Validation;
using S7.Utils;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// An abstract command handler that integrates a validation pipeline into the command execution process.
    /// It extends the base CommandHandler and overrides the validation step to use an IValidationPipeline.
    /// </summary>
    /// <typeparam name="TOptions">The type of options for this command handler.</typeparam>
    /// <typeparam name="TResult">The type of result this command handler produces.</typeparam>
    public abstract class ValidatedCommandHandler<TOptions, TResult> : CommandHandler<TOptions, TResult>
        where TOptions : CommandHandlerOptions
    {
        private readonly IValidationPipeline? _validationPipeline;

        /// <summary>
        /// Initializes a new instance of the <see cref="ValidatedCommandHandler{TOptions, TResult}"/> class.
        /// </summary>
        /// <param name="logger">The logger instance.</param>
        /// <param name="validationPipeline">The validation pipeline to execute. Can be null.</param>
        /// <param name="validator">The legacy validator. Used if the validation pipeline is null.</param>
        protected ValidatedCommandHandler(
            ILogger logger,
            IValidationPipeline? validationPipeline,
            IValidator<TOptions>? validator = null)
            : base(logger, validator)
        {
            _validationPipeline = validationPipeline;
        }

        /// <summary>
        /// Overrides the base validation logic to use the validation pipeline if it's available.
        /// If the pipeline is not provided, it falls back to the base validation behavior.
        /// </summary>
        /// <param name="options">The command options to validate.</param>
        /// <param name="cancellationToken">A token to cancel the operation.</param>
        /// <returns>A <see cref="ValidationResultInfo"/> indicating the result of the validation.</returns>
        protected override async Task<ValidationResultInfo> ValidateOptionsAsync(
            TOptions options,
            CancellationToken cancellationToken = default)
        {
            if (_validationPipeline != null)
            {
                var pipelineResult = await _validationPipeline.ExecuteAsync(options, cancellationToken);
                if (!pipelineResult.IsSuccess)
                {
                    // If the pipeline itself fails, return a generic validation error.
                    return ValidationResultInfo.Failure("Validation pipeline execution failed.");
                }

                if (!pipelineResult.Value.IsValid)
                {
                    // If validation fails, return the errors.
                    var errors = pipelineResult.Value.Errors.Select(e => e.ErrorMessage).ToList();
                    return ValidationResultInfo.Failure(errors);
                }

                return ValidationResultInfo.Success();
            }

            // Fallback to base validation if no pipeline is provided.
            return await base.ValidateOptionsAsync(options, cancellationToken);
        }
    }
}