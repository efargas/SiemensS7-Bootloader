using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Extensions
{
    public static class TaskExtensions
    {
        /// <summary>
        /// Safely executes a task without awaiting it. Logs exceptions to the provided error handler.
        /// </summary>
        /// <param name="task">The task to execute.</param>
        /// <param name="onError">The action to invoke if the task fails.</param>
        public static void FireAndForget(this Task task, Action<Exception>? onError = null)
        {
            _ = task.ContinueWith(t =>
            {
                if (t.IsFaulted && t.Exception != null)
                {
                    onError?.Invoke(t.Exception.GetBaseException());
                }
            }, TaskScheduler.Default);
        }
    }
}
