using System;
using System.Text.Json;

namespace PLCSploit.Core
{
    // Log message categories/enums for filtering
    public enum LogCategory
    {
        Info,
        Warning,
        Error,
        Communication,
        System,
        Debug,
        Other
    }

    // Structured LogEntry class
    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public string Message { get; set; }
        public LogCategory Category { get; set; }

        public LogEntry(string message, LogCategory category)
        {
            Timestamp = DateTime.Now;
            Message = message;
            Category = category;
        }

        public override string ToString() => $"[{Timestamp:HH:mm:ss}] [{Category}] {Message}";

        // JSON serialization for marshalling
        public string ToJson() => JsonSerializer.Serialize(this);
        public static LogEntry FromJson(string json) => JsonSerializer.Deserialize<LogEntry>(json);
    }

    public static class Log
    {
        public static event Action<LogEntry>? MessageAdded;

        private static string EscapeNonPrintable(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;
            var sb = new System.Text.StringBuilder(input.Length * 2);
            foreach (var ch in input)
            {
                if (ch >= 0x20 && ch <= 0x7E)
                {
                    sb.Append(ch);
                }
                else
                {
                    sb.Append("\\x").Append(((int)ch).ToString("X2"));
                }
            }
            return sb.ToString();
        }

        // Main log add function with category
        public static void Add(string message, LogCategory category = LogCategory.Info)
        {
            try
            {
                var sanitized = EscapeNonPrintable(message);
                var entry = new LogEntry(sanitized, category);

                // Persist via centralized logging service (rotation + in-memory)
                LoggingService.Log(entry);

                // Notify subscribers (e.g., GUI) with the structured entry
                MessageAdded?.Invoke(entry);
            }
            catch (Exception ex)
            {
                // Fallback logging to console if the logging system itself fails
                Console.WriteLine($"[Log] Critical logging failure: {ex.Message}");
                Console.WriteLine($"[Log] Original message: {message}");
            }
        }
    }
}
