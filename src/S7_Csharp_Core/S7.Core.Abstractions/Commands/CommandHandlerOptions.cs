using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Base class for all command handler options providing common properties and validation.
    /// </summary>
    public abstract class CommandHandlerOptions
    {
        /// <summary>
        /// Gets or sets the correlation ID for tracking this command execution across the system.
        /// </summary>
        [Required(ErrorMessage = "CorrelationId is required")]
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the cancellation token for the operation.
        /// </summary>
        public CancellationToken CancellationToken { get; set; } = default;

        /// <summary>
        /// Gets or sets additional metadata associated with this command execution.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets or sets the timeout for the command execution in milliseconds.
        /// </summary>
        [Range(1000, int.MaxValue, ErrorMessage = "Timeout must be at least 1000 milliseconds")]
        public int TimeoutMs { get; set; } = 30000; // 30 seconds default

        /// <summary>
        /// Gets or sets whether to enable detailed logging for this command execution.
        /// </summary>
        public bool EnableDetailedLogging { get; set; } = false;

        /// <summary>
        /// Gets or sets the priority level for this command execution.
        /// </summary>
        public CommandPriority Priority { get; set; } = CommandPriority.Normal;

        /// <summary>
        /// Gets or sets the retry policy configuration for this command.
        /// </summary>
        public RetryPolicy? RetryPolicy { get; set; }

        /// <summary>
        /// Validates the command options and returns validation results.
        /// </summary>
        /// <returns>A collection of validation results</returns>
        public virtual IEnumerable<ValidationResult> Validate()
        {
            var context = new ValidationContext(this);
            var results = new List<ValidationResult>();
            Validator.TryValidateObject(this, context, results, true);
            return results;
        }

        /// <summary>
        /// Determines whether the command options are valid.
        /// </summary>
        /// <returns>True if valid, false otherwise</returns>
        public virtual bool IsValid()
        {
            return !Validate().Any();
        }
    }

    /// <summary>
    /// Defines the priority levels for command execution.
    /// </summary>
    public enum CommandPriority
    {
        /// <summary>
        /// Low priority command execution.
        /// </summary>
        Low = 0,

        /// <summary>
        /// Normal priority command execution.
        /// </summary>
        Normal = 1,

        /// <summary>
        /// High priority command execution.
        /// </summary>
        High = 2,

        /// <summary>
        /// Critical priority command execution.
        /// </summary>
        Critical = 3
    }

    /// <summary>
    /// Defines retry policy configuration for command execution.
    /// </summary>
    public class RetryPolicy
    {
        /// <summary>
        /// Gets or sets the maximum number of retry attempts.
        /// </summary>
        [Range(0, 10, ErrorMessage = "MaxRetries must be between 0 and 10")]
        public int MaxRetries { get; set; } = 3;

        /// <summary>
        /// Gets or sets the delay between retry attempts in milliseconds.
        /// </summary>
        [Range(100, 60000, ErrorMessage = "RetryDelayMs must be between 100 and 60000 milliseconds")]
        public int RetryDelayMs { get; set; } = 1000;

        /// <summary>
        /// Gets or sets whether to use exponential backoff for retry delays.
        /// </summary>
        public bool UseExponentialBackoff { get; set; } = true;

        /// <summary>
        /// Gets or sets the types of exceptions that should trigger a retry.
        /// </summary>
        public Type[] RetryableExceptions { get; set; } = Array.Empty<Type>();
    }
}