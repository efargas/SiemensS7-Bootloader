using Avalonia;
using Avalonia.Controls;
using System.Collections.Specialized;
using System.Runtime.CompilerServices;

namespace S7_Csharp_Utility.Behaviors
{
    public static class AutoScrollBehavior
    {
        private static readonly ConditionalWeakTable<INotifyCollectionChanged, ListBox> _associations = new();

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
                    _associations.Add(notifyCollection, listBox);
                    notifyCollection.CollectionChanged += OnCollectionChanged;
                }
                else
                {
                    _associations.Remove(notifyCollection);
                    notifyCollection.CollectionChanged -= OnCollectionChanged;
                }
            }
        }

        private static void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        {
            if (sender is INotifyCollectionChanged collection && _associations.TryGetValue(collection, out var listBox))
            {
                if (listBox.Items is System.Collections.IList items && items.Count > 0)
                {
                    var lastItem = items[items.Count - 1];
                    if (lastItem != null)
                    {
                        listBox.ScrollIntoView(lastItem);
                    }
                }
            }
        }
    }
}
