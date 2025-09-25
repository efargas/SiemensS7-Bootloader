using System;
using System.Threading.Tasks;

namespace S7_Csharp_Utility.Extensions
{
    /// <summary>
    /// Extensions for Task to provide fire-and-forget functionality with proper exception handling.
    /// </summary>
    public static class TaskExtensions
    {
        /// <summary>
        /// Safely executes a task without awaiting it. Logs exceptions to the provided error handler.
        /// This method ensures that unhandled exceptions in fire-and-forget tasks are properly captured
        /// and handled, preventing them from causing application crashes.
        /// </summary>
        /// <param name="task">The task to execute.</param>
        /// <param name="onError">The action to invoke if the task fails. If null, exceptions are silently ignored.</param>
        /// <param name="continueOnCapturedContext">Whether to continue on the captured context. Defaults to false for better performance.</param>
        public static void FireAndForget(this Task task, Action<Exception>? onError = null, bool continueOnCapturedContext = false)
        {
            if (task == null)
                throw new ArgumentNullException(nameof(task));

            _ = task.ContinueWith(t =>
            {
                if (t.IsFaulted && t.Exception != null)
                {
                    // Get the actual exception, unwrapping AggregateException if needed
                    var exception = t.Exception.InnerExceptions.Count == 1 
                        ? t.Exception.InnerExceptions[0] 
                        : t.Exception;
                    
                    try
                    {
                        onError?.Invoke(exception);
                    }
                    catch (Exception handlerException)
                    {
                        // If the error handler itself throws, we need to prevent that from bubbling up
                        // In a real application, you might want to log this to a fallback logger
                        System.Diagnostics.Debug.WriteLine($"Exception in FireAndForget error handler: {handlerException}");
                    }
                }
                else if (t.IsCanceled)
                {
                    // Task was cancelled - this is usually expected behavior, so we don't treat it as an error
                    // unless the caller specifically wants to handle cancellations
                    try
                    {
                        onError?.Invoke(new OperationCanceledException("Fire-and-forget task was cancelled"));
                    }
                    catch (Exception handlerException)
                    {
                        System.Diagnostics.Debug.WriteLine($"Exception in FireAndForget cancellation handler: {handlerException}");
                    }
                }
            }, 
            continueOnCapturedContext ? TaskScheduler.Current : TaskScheduler.Default);
        }

        /// <summary>
        /// Safely executes a task without awaiting it, with a typed exception handler.
        /// </summary>
        /// <typeparam name="TException">The type of exception to handle specifically.</typeparam>
        /// <param name="task">The task to execute.</param>
        /// <param name="onSpecificError">Handler for the specific exception type.</param>
        /// <param name="onOtherError">Handler for other exception types.</param>
        /// <param name="continueOnCapturedContext">Whether to continue on the captured context.</param>
        public static void FireAndForget<TException>(this Task task, 
            Action<TException>? onSpecificError = null, 
            Action<Exception>? onOtherError = null,
            bool continueOnCapturedContext = false) 
            where TException : Exception
        {
            task.FireAndForget(ex =>
            {
                if (ex is TException specificEx)
                {
                    onSpecificError?.Invoke(specificEx);
                }
                else
                {
                    onOtherError?.Invoke(ex);
                }
            }, continueOnCapturedContext);
        }
    }
}
