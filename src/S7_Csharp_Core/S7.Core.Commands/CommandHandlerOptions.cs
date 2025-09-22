using System;

namespace S7.Core.Commands
{
    /// <summary>
    /// Base class for command handler options.
    /// </summary>
    public abstract class CommandHandlerOptions
    {
        /// <summary>
        /// Gets or sets the correlation ID for tracking the command execution.
        /// </summary>
        public string CorrelationId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the timestamp when the command was created.
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets or sets optional metadata for the command.
        /// </summary>
        public object? Metadata { get; set; }
    }
}