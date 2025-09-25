using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
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
        private readonly object _sync = new object();
        private const int MaxLogLines = 2000;
        private readonly Dispatcher _dispatcher;
        private readonly ResourceManagerService? _resourceManager;
        private string _mainLogFile;
        private string _logsPath;
        private const long MaxLogFileSize = 5 * 1024 * 1024; // 5MB

        private readonly ObservableCollection<LogMessage> _allLogMessages = new();
        private bool _filterInfo = true;
        /// <summary>
        /// Indicates whether to display informational messages.
        /// </summary>
        public bool FilterInfo
        {
            get => _filterInfo;
            set
            {
                if (_filterInfo == value) return;
                _filterInfo = value;
                OnPropertyChanged();
                ApplyFilter();
            }
        }

        private bool _filterError = true;
        /// <summary>
        /// Indicates whether to display error and warning messages.
        /// </summary>
        public bool FilterError
        {
            get => _filterError;
            set
            {
                if (_filterError == value) return;
                _filterError = value;
                OnPropertyChanged();
                ApplyFilter();
            }
        }

        private bool _filterDebug = true;
        /// <summary>
        /// Indicates whether to display debug messages.
        /// </summary>
        public bool FilterDebug
        {
            get => _filterDebug;
            set
            {
                if (_filterDebug == value) return;
                _filterDebug = value;
                OnPropertyChanged();
                ApplyFilter();
            }
        }

        public ObservableCollection<LogMessage> LogMessages { get; } = new();


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
        /// Reference to the ListBox for scroll control.
        /// </summary>
        public Avalonia.Controls.ListBox? LogListBox { get; set; }
        /// <summary>
        /// Event triggered when a property value changes.
        /// </summary>
        public event PropertyChangedEventHandler? PropertyChanged;

        /// <summary>
        /// Initializes a new instance of the <see cref="LoggingService"/> class.
        /// </summary>
        /// <param name="dispatcher">The dispatcher to use for UI updates.</param>
        /// <param name="resourceManager">The resource manager service for localized messages. Optional for backward compatibility.</param>
        /// <param name="logsPath">The path where log files should be saved. If null, uses default path.</param>
        public LoggingService(Dispatcher dispatcher, ResourceManagerService? resourceManager = null, string? logsPath = null)
        {
            _dispatcher = dispatcher;
            _resourceManager = resourceManager;
            _logsPath = logsPath ?? Path.Combine(AppContext.BaseDirectory, "logs");
            Directory.CreateDirectory(_logsPath);
            _mainLogFile = Path.Combine(_logsPath, $"PlcMain_{DateTime.Now:yyyyMMdd_HHmmss}.log");
            ClearLogCommand = new Commands.RelayCommand(_ => Clear(), _ => true);
            ExportLogCommand = new Commands.RelayCommand(_ => ExportLogs(), _ => true);
            ScrollToEndCommand = new Commands.RelayCommand(_ => ForceScrollToEnd(), _ => true);
        }

        /// <summary>
        /// Exports the current log to a text file.
        /// </summary>
        private void ExportLogs()
        {
            Directory.CreateDirectory(_logsPath);
            string logFile = Path.Combine(_logsPath, $"exported_{DateTime.Now:yyyyMMdd_HHmmss}.txt");
            List<LogMessage> snapshot;
            lock (_sync)
            {
                snapshot = new List<LogMessage>(_allLogMessages);
            }
            using (var writer = new StreamWriter(logFile, false))
            {
                foreach (var entry in snapshot)
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
            if (string.IsNullOrEmpty(message)) return;

            var entry = new LogMessage
            {
                Timestamp = DateTime.Now,
                Category = category,
                Message = message
            };

            // Handle file logging on background thread
            Task.Run(() =>
            {
                lock (_sync)
                {
                    HandleLogFile(entry);
                }
            });

            // Update UI on UI thread with lower priority to avoid blocking
            _dispatcher.Post(() =>
            {
                lock (_sync)
                {
                    _allLogMessages.Add(entry);

                    if (ShouldBeVisible(entry))
                    {
                        LogMessages.Add(entry);
                    }

                    if (_allLogMessages.Count > MaxLogLines)
                    {
                        var toRemove = _allLogMessages[0];
                        _allLogMessages.RemoveAt(0);
                        LogMessages.Remove(toRemove); // This will do nothing if the item is not in the list
                    }
                }
            }, Avalonia.Threading.DispatcherPriority.Background);
        }

        /// <summary>
        /// Logs a message using a resource key.
        /// </summary>
        /// <param name="resourceKey">The resource key for the message.</param>
        /// <param name="category">The category of the message.</param>
        /// <param name="args">Optional format arguments for the message.</param>
        public void LogWithKey(string resourceKey, LogCategory category = LogCategory.Info, params object[] args)
        {
            if (string.IsNullOrEmpty(resourceKey)) return;

            string message;
            if (_resourceManager != null)
            {
                message = args.Length > 0 
                    ? _resourceManager.GetFormattedLogMessage(resourceKey, args)
                    : _resourceManager.GetLogMessage(resourceKey);
            }
            else
            {
                // Fallback when ResourceManagerService is not available
                message = args.Length > 0 
                    ? $"{resourceKey} [{string.Join(", ", args)}]"
                    : resourceKey;
            }

            Log(message, category);
        }

        /// <summary>
        /// Logs an error message using a resource key.
        /// </summary>
        /// <param name="resourceKey">The resource key for the error message.</param>
        /// <param name="args">Optional format arguments for the message.</param>
        public void LogError(string resourceKey, params object[] args)
        {
            if (string.IsNullOrEmpty(resourceKey)) return;

            string message;
            if (_resourceManager != null)
            {
                message = args.Length > 0 
                    ? _resourceManager.GetFormattedErrorMessage(resourceKey, args)
                    : _resourceManager.GetErrorMessage(resourceKey);
            }
            else
            {
                // Fallback when ResourceManagerService is not available
                message = args.Length > 0 
                    ? $"{resourceKey} [{string.Join(", ", args)}]"
                    : resourceKey;
            }

            Log(message, LogCategory.Error);
        }

        /// <summary>
        /// Handles writing the log entry to a file, with rotation.
        /// </summary>
        /// <param name="entry">The log entry to write.</param>
        private void HandleLogFile(LogMessage entry)
        {
            RotateIfNeeded();
            File.AppendAllText(_mainLogFile, $"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category} {entry.Message}{Environment.NewLine}");
        }

        private void RotateIfNeeded()
        {
            if (!File.Exists(_mainLogFile)) return;
            var fi = new FileInfo(_mainLogFile);
            if (fi.Length >= MaxLogFileSize)
            {
                var logDir = Path.GetDirectoryName(_mainLogFile);
                if (logDir != null)
                {
                    _mainLogFile = Path.Combine(logDir, $"PlcMain_{DateTime.Now:yyyyMMdd_HHmmss}.log");
                }
            }
        }

        /// <summary>
        /// Updates the logs path and creates a new log file in the new location.
        /// </summary>
        /// <param name="newLogsPath">The new path where log files should be saved.</param>
        public void UpdateLogsPath(string newLogsPath)
        {
            if (string.IsNullOrWhiteSpace(newLogsPath))
                return;

            _logsPath = newLogsPath;
            Directory.CreateDirectory(_logsPath);
            _mainLogFile = Path.Combine(_logsPath, $"PlcMain_{DateTime.Now:yyyyMMdd_HHmmss}.log");

            Log($"Log path updated to: {_logsPath}", LogCategory.Info);
        }

        /// <summary>
        /// Updates the log filter settings and applies them.
        /// </summary>
        /// <param name="showInfo">Whether to show info messages.</param>
        /// <param name="showError">Whether to show error and warning messages.</param>
        /// <param name="showDebug">Whether to show debug messages.</param>
        public void UpdateLogFilter(bool showInfo, bool showError, bool showDebug)
        {
            FilterInfo = showInfo;
            FilterError = showError;
            FilterDebug = showDebug;
        }

        /// <summary>
        /// Gets all log messages as a single text string.
        /// </summary>
        public string LogText
        {
            get
            {
                List<LogMessage> snapshot;
                lock (_sync)
                {
                    snapshot = new List<LogMessage>(_allLogMessages);
                }

                var sb = new StringBuilder();
                foreach (var entry in snapshot)
                {
                    sb.AppendLine($"[{entry.Timestamp:yyyy-MM-dd HH:mm:ss}] {entry.Category}: {entry.Message}");
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Clears the log.
        /// </summary>
        public void Clear()
        {
            _dispatcher.Post(() =>
            {
                lock (_sync)
                {
                    _allLogMessages.Clear();
                    LogMessages.Clear();
                }
            });
        }

        private void ApplyFilter()
        {
            List<LogMessage> snapshot;
            lock (_sync)
            {
                snapshot = new List<LogMessage>(_allLogMessages);
            }

            var filtered = snapshot.Where(ShouldBeVisible).ToList();

            _dispatcher.Post(() =>
            {
                lock (_sync)
                {
                    LogMessages.Clear();
                    foreach (var item in filtered)
                    {
                        LogMessages.Add(item);
                    }
                }
                ScrollToEnd?.Invoke();
            });
        }

        private bool ShouldBeVisible(LogMessage entry)
        {
            return entry.Category switch
            {
                LogCategory.Info => FilterInfo,
                LogCategory.Warning => FilterError,
                LogCategory.Error => FilterError,
                LogCategory.Debug => FilterDebug,
                _ => true
            };
        }

        /// <summary>
        /// Forces scroll to end and re-enables auto-scroll.
        /// </summary>
        private void ForceScrollToEnd()
        {
            if (LogListBox != null)
            {
                Behaviors.AutoScrollBehavior.ForceScrollToEnd(LogListBox);
            }
            ScrollToEnd?.Invoke();
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
