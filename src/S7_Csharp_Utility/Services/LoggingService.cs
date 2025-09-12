using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using Avalonia.Threading;

namespace S7_Csharp_Utility.Services
{
    /// <summary>
    /// Defines the category of a log message.
    /// </summary>
    public enum LogCategory { Info, Warning, Error, Debug }

    /// <summary>
    /// Represents a single log message.
    /// </summary>
    public class LogMessage
    {
        /// <summary>
        /// The timestamp of the log message.
        /// </summary>
        public DateTime Timestamp { get; set; }
        /// <summary>
        /// The category of the log message.
        /// </summary>
        public LogCategory Category { get; set; }
        /// <summary>
        /// The content of the log message.
        /// </summary>
        public string Message { get; set; } = string.Empty;
    }

    /// <summary>
    /// Service for handling application logging.
    /// </summary>
    public class LoggingService : INotifyPropertyChanged
    {
        private readonly List<LogMessage> _allLogMessages = new List<LogMessage>();
        private const int MaxLogLines = 2000;
        private readonly Dispatcher _dispatcher;
        private string _logText = string.Empty;

        /// <summary>
        /// Indicates whether to display informational messages.
        /// </summary>
        public bool FilterInfo { get; set; } = true;
        /// <summary>
        /// Indicates whether to display error messages.
        /// </summary>
        public bool FilterError { get; set; } = true;
        /// <summary>
        /// Indicates whether to display debug messages.
        /// </summary>
        public bool FilterDebug { get; set; } = true;

        /// <summary>
        /// The formatted log text to be displayed in the UI.
        /// </summary>
        public string LogText
        {
            get => _logText;
            private set
            {
                _logText = value;
                OnPropertyChanged();
            }
        }

        /// <summary>
        /// Command to clear the log.
        /// </summary>
        public System.Windows.Input.ICommand ClearLogCommand { get; }
        /// <summary>
        /// Command to export the log to a file.
        /// </summary>
        public System.Windows.Input.ICommand ExportLogCommand { get; }
        /// <summary>
        /// Command to scroll to the end of the log.
        /// </summary>
        public System.Windows.Input.ICommand ScrollToEndCommand { get; }
        /// <summary>
        /// Event triggered to scroll to the end of the log.
        /// </summary>
        public event Action? ScrollToEnd;
        /// <summary>
        /// Event triggered when a property value changes.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Initializes a new instance of the <see cref="LoggingService"/> class.
        /// </summary>
        /// <param name="dispatcher">The dispatcher to use for UI updates.</param>
        public LoggingService(Dispatcher dispatcher)
        {
            _dispatcher = dispatcher;
            ClearLogCommand = new Commands.RelayCommand(_ => Clear(), _ => true);
            ExportLogCommand = new Commands.RelayCommand(_ => ExportLogs(), _ => true);
            ScrollToEndCommand = new Commands.RelayCommand(_ => ScrollToEnd?.Invoke(), _ => true);
        }

        /// <summary>
        /// Exports the current log to a text file.
        /// </summary>
        private void ExportLogs()
        {
            string logDir = System.IO.Path.Combine(AppContext.BaseDirectory, "logs");
            System.IO.Directory.CreateDirectory(logDir);
            string logFile = System.IO.Path.Combine(logDir, $"exported_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            using (var writer = new System.IO.StreamWriter(logFile, false))
            {
                foreach (var entry in _allLogMessages)
                {
                    writer.WriteLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category} {entry.Message}");
                }
            }
        }

        /// <summary>
        /// Logs a message.
        /// </summary>
        /// <param name="message">The message to log.</param>
        /// <param name="category">The category of the message.</param>
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

        /// <summary>
        /// Updates the log text based on the current filter settings.
        /// </summary>
        public void UpdateLogFilter()
        {
            var sb = new StringBuilder();
            
            foreach (var entry in _allLogMessages)
            {
                if ((FilterInfo && entry.Category == LogCategory.Info)
                    || (FilterError && entry.Category == LogCategory.Error)
                    || (FilterDebug && entry.Category == LogCategory.Debug)
                    || (FilterInfo && entry.Category == LogCategory.Warning))
                {
                    var categoryStr = entry.Category switch
                    {
                        LogCategory.Info => "[INFO]",
                        LogCategory.Error => "[ERROR]",
                        LogCategory.Debug => "[DEBUG]",
                        LogCategory.Warning => "[WARN]",
                        _ => "[INFO]"
                    };
                    sb.AppendLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {categoryStr} {entry.Message}");
                }
            }
            
            LogText = sb.ToString();
        }

        /// <summary>
        /// Handles writing the log entry to a file, with rotation.
        /// </summary>
        /// <param name="entry">The log entry to write.</param>
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

        /// <summary>
        /// Clears the log.
        /// </summary>
        public void Clear()
        {
            _allLogMessages.Clear();
            LogText = string.Empty;
        }

        /// <summary>
        /// Triggers the PropertyChanged event.
        /// </summary>
        /// <param name="propertyName">The name of the property that changed.</param>
        protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
