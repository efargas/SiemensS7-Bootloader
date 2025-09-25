using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Threading;
using Avalonia.VisualTree;
using System;
using System.Collections.Specialized;
using System.Collections.Generic;

namespace S7_Csharp_Utility.Behaviors
{
    public static class AutoScrollBehavior
    {
        public static readonly AttachedProperty<bool> IsEnabledProperty =
            AvaloniaProperty.RegisterAttached<ListBox, bool>("IsEnabled", typeof(AutoScrollBehavior));

        private static readonly Dictionary<ListBox, AutoScrollState> _states = new();

        public static bool GetIsEnabled(ListBox listBox) =>
            listBox.GetValue(IsEnabledProperty);

        public static void SetIsEnabled(ListBox listBox, bool value) =>
            listBox.SetValue(IsEnabledProperty, value);

        static AutoScrollBehavior()
        {
            IsEnabledProperty.Changed.AddClassHandler<ListBox>(OnIsEnabledChanged);
        }

        private static void OnIsEnabledChanged(ListBox listBox, AvaloniaPropertyChangedEventArgs e)
        {
            if (e.NewValue is bool isEnabled)
            {
                if (isEnabled)
                {
                    AttachBehavior(listBox);
                }
                else
                {
                    DetachBehavior(listBox);
                }
            }
        }

        private static void AttachBehavior(ListBox listBox)
        {
            if (_states.ContainsKey(listBox))
                return;

            var state = new AutoScrollState();
            _states[listBox] = state;

            // Subscribe to collection changes
            if (listBox.Items is INotifyCollectionChanged notifyCollection)
            {
                state.CollectionChangedHandler = (sender, e) => OnCollectionChanged(listBox, e);
                notifyCollection.CollectionChanged += state.CollectionChangedHandler;
            }

            // Subscribe to scroll events to detect user interaction
            listBox.Loaded += (sender, e) => OnListBoxLoaded(listBox);
            listBox.Unloaded += (sender, e) => DetachBehavior(listBox);
        }

        private static void OnListBoxLoaded(ListBox listBox)
        {
            if (!_states.TryGetValue(listBox, out var state))
                return;

            // Find the ScrollViewer inside the ListBox
            var scrollViewer = FindScrollViewer(listBox);
            if (scrollViewer != null)
            {
                state.ScrollViewer = scrollViewer;
                scrollViewer.ScrollChanged += (sender, e) => OnScrollChanged(listBox, e);
            }
        }

        private static ScrollViewer? FindScrollViewer(Control control)
        {
            if (control is ScrollViewer scrollViewer)
                return scrollViewer;

            // Use visual tree traversal instead of logical tree
            if (control.GetVisualChildren() != null)
            {
                foreach (var child in control.GetVisualChildren())
                {
                    if (child is Control childControl)
                    {
                        var result = FindScrollViewer(childControl);
                        if (result != null)
                            return result;
                    }
                }
            }

            return null;
        }

        private static void OnScrollChanged(ListBox listBox, ScrollChangedEventArgs e)
        {
            if (!_states.TryGetValue(listBox, out var state) || state.ScrollViewer == null)
                return;

            // Check if user scrolled (not programmatic scroll)
            if (!state.IsProgrammaticScroll)
            {
                // Check if user is at the bottom
                var scrollViewer = state.ScrollViewer;
                var isAtBottom = Math.Abs(scrollViewer.Offset.Y - scrollViewer.ScrollBarMaximum.Y) < 1.0;
                state.IsAutoScrollEnabled = isAtBottom;
            }

            state.IsProgrammaticScroll = false;
        }

        private static void OnCollectionChanged(ListBox listBox, NotifyCollectionChangedEventArgs e)
        {
            if (!_states.TryGetValue(listBox, out var state))
                return;

            // Only auto-scroll if enabled and items were added
            if (state.IsAutoScrollEnabled && 
                (e.Action == NotifyCollectionChangedAction.Add || e.Action == NotifyCollectionChangedAction.Reset))
            {
                Dispatcher.UIThread.Post(() => ScrollToEnd(listBox), DispatcherPriority.Background);
            }
        }

        private static void ScrollToEnd(ListBox listBox)
        {
            if (!_states.TryGetValue(listBox, out var state) || state.ScrollViewer == null)
                return;

            if (listBox.Items?.Count > 0)
            {
                state.IsProgrammaticScroll = true;
                var lastItem = listBox.Items[listBox.Items.Count - 1];
                if (lastItem != null)
                {
                    listBox.ScrollIntoView(lastItem);
                }
            }
        }

        private static void DetachBehavior(ListBox listBox)
        {
            if (!_states.TryGetValue(listBox, out var state))
                return;

            // Unsubscribe from collection changes
            if (listBox.Items is INotifyCollectionChanged notifyCollection && state.CollectionChangedHandler != null)
            {
                notifyCollection.CollectionChanged -= state.CollectionChangedHandler;
            }

            _states.Remove(listBox);
        }

        public static void ForceScrollToEnd(ListBox listBox)
        {
            if (_states.TryGetValue(listBox, out var state))
            {
                state.IsAutoScrollEnabled = true;
                ScrollToEnd(listBox);
            }
        }

        private class AutoScrollState
        {
            public bool IsAutoScrollEnabled { get; set; } = true;
            public bool IsProgrammaticScroll { get; set; } = false;
            public ScrollViewer? ScrollViewer { get; set; }
            public NotifyCollectionChangedEventHandler? CollectionChangedHandler { get; set; }
        }
    }
}
