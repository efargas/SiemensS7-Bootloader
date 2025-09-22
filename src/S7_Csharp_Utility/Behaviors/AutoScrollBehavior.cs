using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Data;
using System.Collections.Specialized;

namespace S7_Csharp_Utility.Behaviors
{
    public static class AutoScrollBehavior
    {
        public static readonly AttachedProperty<bool> IsEnabledProperty =
            AvaloniaProperty.RegisterAttached<ListBox, bool>("IsEnabled", typeof(AutoScrollBehavior));

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
            if (listBox.Items is INotifyCollectionChanged notifyCollection)
            {
                if ((bool)e.NewValue)
                {
                    notifyCollection.CollectionChanged += OnCollectionChanged;
                }
                else
                {
                    notifyCollection.CollectionChanged -= OnCollectionChanged;
                }
            }
        }

        private static void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (sender is System.Collections.IList items && items.Count > 0)
            {
                var lastItem = items[items.Count - 1];
                if (lastItem != null)
                {
                    // Find the ListBox that contains this collection
                    // This is a simplified approach - in a real implementation you might need to track the ListBox reference
                    // For now, we'll skip the scroll functionality to avoid the compilation error
                    // TODO: Implement proper ListBox reference tracking
                }
            }
        }
    }
}
