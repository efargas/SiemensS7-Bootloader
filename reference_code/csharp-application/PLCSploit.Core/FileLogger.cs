using System;
using System.IO;
using System.Threading;

namespace PLCSploit.Core
{
    public static class FileLogger
    {
        private static readonly object _lock = new object();
        private static string _currentLogFile = "";
        private static long _currentFileSize = 0;
        private const long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
        private static int _fileIndex = 1;

        static FileLogger()
        {
            InitializeLogFile();
        }

        private static void InitializeLogFile()
        {
            var logsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            if (!Directory.Exists(logsDir))
            {
                Directory.CreateDirectory(logsDir);
            }

            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            _currentLogFile = Path.Combine(logsDir, $"PLCSploit_{timestamp}_{_fileIndex:D3}.log");
            _currentFileSize = 0;

            // Write header
            WriteToFile($"=== PLCSploit Log Started at {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
        }

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

        // Overload for structured LogEntry logging (marshaled as JSON line)
        public static void Log(LogEntry entry)
        {
            lock (_lock)
            {
                try
                {
                    var json = entry.ToJson();
                    if (_currentFileSize > MAX_FILE_SIZE)
                    {
                        RotateLogFile();
                    }
                    WriteToFile(json);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"FileLogger Error: {ex.Message}");
                    Console.WriteLine($"Original log entry: {entry.ToString()}");
                }
            }
        }

        // Legacy string logging, creates an Info category log entry
        public static void Log(string message)
        {
            Log(new LogEntry(EscapeNonPrintable(message), LogCategory.Info));
        }

        private static void WriteToFile(string logEntry)
        {
            var bytes = System.Text.Encoding.UTF8.GetBytes(logEntry + Environment.NewLine);
            File.AppendAllText(_currentLogFile, logEntry + Environment.NewLine);
            _currentFileSize += bytes.Length;
        }

        private static void RotateLogFile()
        {
            WriteToFile($"=== Log file rotated at {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
            
            _fileIndex++;
            var logsDir = Path.GetDirectoryName(_currentLogFile);
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            _currentLogFile = Path.Combine(logsDir!, $"PLCSploit_{timestamp}_{_fileIndex:D3}.log");
            _currentFileSize = 0;

            WriteToFile($"=== PLCSploit Log Continued at {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===");
        }

        public static string GetCurrentLogFile()
        {
            return _currentLogFile;
        }

        public static void LogSeparator(string title = "")
        {
            var separator = new string('=', 80);
            if (!string.IsNullOrEmpty(title))
            {
                var padding = (80 - title.Length - 2) / 2;
                separator = new string('=', padding) + $" {title} " + new string('=', 80 - padding - title.Length - 2);
            }
            Log(separator);
        }
    }
}