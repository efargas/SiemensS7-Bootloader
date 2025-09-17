using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;
using PLCSploit.Core;

namespace PLCSploit.Gui.ViewModels
{
    public class LogFilterOption
    {
        public string Display { get; }
        public LogCategory? Value { get; }
        public LogFilterOption(string display, LogCategory? value)
        {
            Display = display;
            Value = value;
        }
        public override string ToString() => Display;
    }

    public class MainViewModel : ViewModelBase, INotifyPropertyChanged
    {
        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

        // All logs collected from the system
        public ObservableCollection<LogEntry> Logs { get; } = new ObservableCollection<LogEntry>();
        // Filtered view bound to UI
        public ObservableCollection<LogEntry> FilteredLogs { get; } = new ObservableCollection<LogEntry>();

        public ModbusViewModel Modbus { get; }
        public ExploitViewModel Exploit { get; }
        public SocatViewModel Socat { get; }
        public SocatViewerViewModel SocatViewer { get; }

        private LogCategory? _selectedCategory;
        public LogCategory? SelectedCategory
        {
            get => _selectedCategory;
            private set
            {
                _selectedCategory = value;
                OnPropertyChanged(nameof(SelectedCategory));
            }
        }

        public ObservableCollection<LogFilterOption> LogFilters { get; } = new ObservableCollection<LogFilterOption>();

        private LogFilterOption _selectedLogFilter;
        public LogFilterOption SelectedLogFilter
        {
            get => _selectedLogFilter;
            set
            {
                if (_selectedLogFilter == value) return;
                _selectedLogFilter = value;
                SelectedCategory = value?.Value;
                UpdateFilter();
                OnPropertyChanged(nameof(SelectedLogFilter));
            }
        }

        public MainViewModel()
        {
            SocatViewer = new SocatViewerViewModel();
            Modbus = new ModbusViewModel();
            Exploit = new ExploitViewModel(Modbus);
            Socat = new SocatViewModel(SocatViewer);

            // Build filter options (All + enum values)
            LogFilters.Add(new LogFilterOption("All", null));
            foreach (var cat in Enum.GetValues(typeof(LogCategory)).Cast<LogCategory>())
                LogFilters.Add(new LogFilterOption(cat.ToString(), cat));
            _selectedLogFilter = LogFilters.First();
            SelectedCategory = null; // default to All

            // Keep filtered view in sync with additions
            Logs.CollectionChanged += OnLogsCollectionChanged;
        }

        private void OnLogsCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            switch (e.Action)
            {
                case NotifyCollectionChangedAction.Add:
                    foreach (var obj in e.NewItems)
                    {
                        if (obj is LogEntry entry)
                        {
                            if (SelectedCategory == null || entry.Category == SelectedCategory)
                                FilteredLogs.Add(entry);
                        }
                    }
                    break;
                case NotifyCollectionChangedAction.Remove:
                case NotifyCollectionChangedAction.Reset:
                case NotifyCollectionChangedAction.Replace:
                case NotifyCollectionChangedAction.Move:
                    // For simplicity, rebuild on complex changes
                    RebuildFilter();
                    break;
            }
        }

        private void UpdateFilter()
        {
            RebuildFilter();
        }

        private void RebuildFilter()
        {
            FilteredLogs.Clear();
            if (SelectedCategory == null)
            {
                foreach (var e in Logs)
                    FilteredLogs.Add(e);
            }
            else
            {
                foreach (var e in Logs.Where(l => l.Category == SelectedCategory))
                    FilteredLogs.Add(e);
            }
            OnPropertyChanged(nameof(FilteredLogs));
        }
    }
}
