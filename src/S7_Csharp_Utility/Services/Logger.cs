using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace S7_Csharp_Utility
{
    /// <summary>
    /// Represents the severity level of a log entry.
    /// </summary>
    public enum LogLevel { Info, Warning, Error, Debug }

    /// <summary>
    /// Represents a single log entry.
    /// </summary>
    public class LogEntry
    {
        /// <summary>
        /// The timestamp of the log entry.
        /// </summary>
        public DateTime Timestamp { get; set; }
        /// <summary>
        /// The severity level of the log entry.
        /// </summary>
        public LogLevel Level { get; set; }
        /// <summary>
        /// The message of the log entry.
        /// </summary>
        public string Message { get; set; } = string.Empty;
        /// <summary>
        /// Returns a string representation of the log entry.
        /// </summary>
        /// <returns>A string representation of the log entry.</returns>
        public override string ToString()
        {
            return $"[{Timestamp:HH:mm:ss}] [{Level}] {Message}";
        }
    }

    /// <summary>
    /// A simple logger class.
    /// </summary>
    public class Logger
    {
        private readonly List<LogEntry> _history = new();
        /// <summary>
        /// Gets or sets a value indicating whether to enable debug logging.
        /// </summary>
        public bool EnableDebug { get; set; } = false;
        /// <summary>
        /// An action to be called when a log entry is added.
        /// </summary>
        public Action<LogEntry>? OnLog;

        /// <summary>
        /// Logs a message with the specified log level.
        /// </summary>
        /// <param name="level">The log level.</param>
        /// <param name="message">The message to log.</param>
        public void Log(LogLevel level, string message)
        {
            if (level == LogLevel.Debug && !EnableDebug)
                return;
            var entry = new LogEntry { Timestamp = DateTime.Now, Level = level, Message = message };
            _history.Add(entry);
            OnLog?.Invoke(entry);
        }
        /// <summary>
        /// Logs an informational message.
        /// </summary>
        /// <param name="msg">The message to log.</param>
        public void Info(string msg) => Log(LogLevel.Info, msg);
        /// <summary>
        /// Logs a warning message.
        /// </summary>
        /// <param name="msg">The message to log.</param>
        public void Warn(string msg) => Log(LogLevel.Warning, msg);
        /// <summary>
        /// Logs an error message.
        /// </summary>
        /// <param name="msg">The message to log.</param>
        public void Error(string msg) => Log(LogLevel.Error, msg);
        /// <summary>
        /// Logs a debug message.
        /// </summary>
        /// <param name="msg">The message to log.</param>
        public void Debug(string msg) => Log(LogLevel.Debug, msg);
        /// <summary>
        /// Gets all log entries.
        /// </summary>
        public IEnumerable<LogEntry> All => _history;
        /// <summary>
        /// Exports the log to a file.
        /// </summary>
        /// <param name="filePath">The path to the file.</param>
        public void Export(string filePath)
        {
            File.WriteAllLines(filePath, _history.ConvertAll(e => e.ToString()));
        }
        /// <summary>
        /// Clears the log history.
        /// </summary>
        public void Clear() => _history.Clear();
    }
}
