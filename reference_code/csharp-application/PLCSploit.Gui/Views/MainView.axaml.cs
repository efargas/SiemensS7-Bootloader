using System;
using System.ComponentModel;
using Avalonia.Controls;
using PLCSploit.Gui.ViewModels;

namespace PLCSploit.Gui.Views
{
    public partial class MainView : Window
    {
        private ListBox? _generalLogsList;
        private ListBox? _socatLogsList;

        public MainView()
        {
            InitializeComponent();
            Closing += OnClosing;
            this.Loaded += (sender, e) =>
            {
                // Get references to the ListBoxes for auto-scrolling
                _generalLogsList = this.FindControl<ListBox>("GeneralLogsList");
                _socatLogsList = this.FindControl<ListBox>("SocatLogsList");

                if (DataContext is MainViewModel vm)
                {
                    Core.Log.MessageAdded += (entry) =>
                    {
                        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                        {
                            vm.Logs.Add(entry);
                            if (vm.Logs.Count > 1000)
                            {
                                vm.Logs.RemoveAt(0);
                            }
                            
                            // Auto-scroll to the latest message
                            ScrollToBottom(_generalLogsList);
                        });
                    };

                    // Auto-scroll for socat messages too
                    vm.SocatViewer.SocatMessages.CollectionChanged += (sender, e) =>
                    {
                        if (e.Action == System.Collections.Specialized.NotifyCollectionChangedAction.Add)
                        {
                            Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                            {
                                ScrollToBottom(_socatLogsList);
                            });
                        }
                    };
                }
            };
        }

        private void ScrollToBottom(ListBox? listBox)
        {
            if (listBox?.Items?.Count > 0)
            {
                try
                {
                    var lastItem = listBox.Items[listBox.Items.Count - 1];
                    listBox.ScrollIntoView(lastItem);
                }
                catch
                {
                    // Ignore scrolling errors
                }
            }
        }

        private void OnClosing(object? sender, CancelEventArgs e)
        {
            // Clean shutdown - stop socat processes
            if (DataContext is MainViewModel mainViewModel)
            {
                try
                {
                    mainViewModel.Socat.StopCommand.Execute().Subscribe();
                    mainViewModel.Socat.KillAllCommand.Execute().Subscribe();
                }
                catch
                {
                    // Ignore errors during shutdown
                }
            }
        }
    }
}
