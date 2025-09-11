using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Services
{
    public enum LogCategory { Info, Warning, Error, Debug }

    public class LogMessage
    {
        public DateTime Timestamp { get; set; }
        public LogCategory Category { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    public class LoggingService
    {
        private readonly List<LogMessage> _allLogMessages = new List<LogMessage>();
        private const int MaxLogLines = 2000;
        private readonly Dispatcher _dispatcher;

        public ObservableCollection<LogMessage> LogMessages { get; } = new ObservableCollection<LogMessage>();

        public bool FilterInfo { get; set; } = true;
        public bool FilterError { get; set; } = true;
        public bool FilterDebug { get; set; } = true;

        public LoggingService(Dispatcher dispatcher)
        {
            _dispatcher = dispatcher;
        }

        public void Log(string message, LogCategory category = LogCategory.Info)
        {
            var entry = new LogMessage
            {
                Timestamp = DateTime.Now,
                Category = category,
                Message = message
            };

            _allLogMessages.Add(entry);
            if (_allLogMessages.Count > MaxLogLines)
            {
                _allLogMessages.RemoveAt(0);
            }

            _dispatcher.Post(() =>
            {
                UpdateLogFilter();
            });

            HandleLogFile(entry);
        }

        public void UpdateLogFilter()
        {
            LogMessages.Clear();
            foreach (var entry in _allLogMessages)
            {
                if ((FilterInfo && entry.Category == LogCategory.Info)
                    || (FilterError && entry.Category == LogCategory.Error)
                    || (FilterDebug && entry.Category == LogCategory.Debug))
                {
                    LogMessages.Add(entry);
                }
            }
        }

        private void HandleLogFile(LogMessage entry)
        {
            string logDir = Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(logDir);
            string logFile = Path.Combine(logDir, "log.txt");
            long maxSize = 5 * 1024 * 1024; // 5 MB
            if (File.Exists(logFile) && new FileInfo(logFile).Length > maxSize)
            {
                int idx = 1;
                string newLogFile;
                do
                {
                    newLogFile = Path.Combine(logDir, $"log_{idx}.txt");
                    idx++;
                }
                while (File.Exists(newLogFile));
                File.Move(logFile, newLogFile);
            }
            File.AppendAllText(logFile, $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category} {entry.Message}{Environment.NewLine}");
        }

        public void Clear()
        {
            _allLogMessages.Clear();
            UpdateLogFilter();
        }
    }
}
