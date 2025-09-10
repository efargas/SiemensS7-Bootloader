using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace S7_Csharp_Utility
{
    public enum LogLevel { Info, Warning, Error, Debug }

    public class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public LogLevel Level { get; set; }
        public string Message { get; set; }
        public override string ToString()
        {
            return $"[{Timestamp:HH:mm:ss}] [{Level}] {Message}";
        }
    }

    public class Logger
    {
        private readonly List<LogEntry> _history = new();
        public bool EnableDebug { get; set; } = false;
        public Action<LogEntry>? OnLog;

        public void Log(LogLevel level, string message)
        {
            if (level == LogLevel.Debug && !EnableDebug)
                return;
            var entry = new LogEntry { Timestamp = DateTime.Now, Level = level, Message = message };
            _history.Add(entry);
            OnLog?.Invoke(entry);
        }
        public void Info(string msg) => Log(LogLevel.Info, msg);
        public void Warn(string msg) => Log(LogLevel.Warning, msg);
        public void Error(string msg) => Log(LogLevel.Error, msg);
        public void Debug(string msg) => Log(LogLevel.Debug, msg);
        public IEnumerable<LogEntry> All => _history;
        public void Export(string filePath)
        {
            File.WriteAllLines(filePath, _history.ConvertAll(e => e.ToString()));
        }
        public void Clear() => _history.Clear();
    }
}
