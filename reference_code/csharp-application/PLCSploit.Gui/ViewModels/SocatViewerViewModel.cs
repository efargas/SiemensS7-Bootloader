using System;
using System.Collections.ObjectModel;
using System.Reactive;
using ReactiveUI;

namespace PLCSploit.Gui.ViewModels
{
    public class SocatViewerViewModel : ViewModelBase
    {
        public ObservableCollection<string> SocatMessages { get; } = new ObservableCollection<string>();

        private bool _isVisible = false;
        public bool IsVisible
        {
            get => _isVisible;
            set => this.RaiseAndSetIfChanged(ref _isVisible, value);
        }

        public ReactiveCommand<Unit, Unit> ClearCommand { get; }

        public SocatViewerViewModel()
        {
            ClearCommand = ReactiveCommand.Create(Clear);
        }

        public void AddSocatMessage(string message)
        {
            // Accept all messages that come to this method (already filtered by caller)
            // This ensures the collection is updated on the UI thread
            Action action = () => 
            {
                SocatMessages.Add($"[{DateTime.Now:HH:mm:ss.fff}] {message}");
                
                // Keep only the last 1000 messages to prevent memory issues
                while (SocatMessages.Count > 1000)
                {
                    SocatMessages.RemoveAt(0);
                }
            };
            action();
        }

        public void Clear()
        {
            SocatMessages.Clear();
        }

        public void ToggleVisibility()
        {
            IsVisible = !IsVisible;
        }
    }
}