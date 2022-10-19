using System;
using System.Windows;
using System.Windows.Controls;
namespace UE4_Patcher
{
    class Dispatchers
    {
        public static void btnIsEnabled(Button button, bool isEnabled) => button.Dispatcher.BeginInvoke(new Action(() => { button.IsEnabled = isEnabled; }));
        public static void labelContent(Label label, string Content) => label.Dispatcher.BeginInvoke(new Action(() => { label.Content = Content; }));
        public static void buttonVisibility(Button button, Visibility vis) => button.Dispatcher.BeginInvoke(new Action(() => { button.Visibility = vis; }));
        public static void textBlock(TextBlock tb, string text) => tb.Dispatcher.BeginInvoke(new Action(() => { tb.Text = text; }));
    }
}
