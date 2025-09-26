using System;
using System.Linq;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace S7.Core.Abstractions.Commands
{
    /// <summary>
    /// Defines a contract for command handlers to register their dependencies and configure services.
    /// </summary>
    public interface ICommandSetup
    {
        /// <summary>
        /// Sets up the command handler by registering dependencies and configuring services.
        /// This method should be called during application startup to ensure proper dependency injection.
        /// </summary>
        /// <param name="host">The host builder for dependency injection configuration</param>
        static abstract void SetupCommand(IHost host);
    }

    /// <summary>
    /// Defines a contract for command handlers to register their dependencies using service collection.
    /// This interface provides an alternative setup method for scenarios where IHost is not available.
    /// </summary>
    public interface ICommandServiceSetup
    {
        /// <summary>
        /// Sets up the command handler by registering dependencies in the service collection.
        /// This method should be called during application startup to ensure proper dependency injection.
        /// </summary>
        /// <param name="services">The service collection for dependency registration</param>
        static abstract void SetupServices(IServiceCollection services);
    }

    /// <summary>
    /// Provides extension methods for command setup operations.
    /// </summary>
    public static class CommandSetupExtensions
    {
        /// <summary>
        /// Registers a command handler and its dependencies in the service collection.
        /// </summary>
        /// <typeparam name="THandler">The type of command handler to register</typeparam>
        /// <typeparam name="TOptions">The type of options for the command handler</typeparam>
        /// <param name="services">The service collection</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddCommandHandler<THandler, TOptions>(this IServiceCollection services)
            where THandler : CommandHandler<TOptions>
            where TOptions : CommandHandlerOptions
        {
            // Register the command handler as a transient service
            services.AddTransient<THandler>();

            // Register any additional services specific to this command handler
            // This can be overridden by implementing ICommandServiceSetup
            if (typeof(THandler).IsAssignableTo(typeof(ICommandServiceSetup)))
            {
                // Use reflection to call the static SetupServices method
                var setupMethod = typeof(THandler).GetMethod(nameof(ICommandServiceSetup.SetupServices));
                setupMethod?.Invoke(null, new object[] { services });
            }

            return services;
        }

        /// <summary>
        /// Registers multiple command handlers in the service collection.
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <param name="handlerTypes">The types of command handlers to register</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddCommandHandlers(this IServiceCollection services, params Type[] handlerTypes)
        {
            foreach (var handlerType in handlerTypes)
            {
                if (handlerType.IsAbstract || handlerType.IsInterface)
                    continue;

                // Find the base CommandHandler<TOptions> type
                var baseType = handlerType.BaseType;
                while (baseType != null && (!baseType.IsGenericType || baseType.GetGenericTypeDefinition() != typeof(CommandHandler<>)))
                {
                    baseType = baseType.BaseType;
                }

                if (baseType != null)
                {
                    services.AddTransient(handlerType);

                    // Call setup method if available
                    if (handlerType.IsAssignableTo(typeof(ICommandServiceSetup)))
                    {
                        var setupMethod = handlerType.GetMethod(nameof(ICommandServiceSetup.SetupServices));
                        setupMethod?.Invoke(null, new object[] { services });
                    }
                }
            }

            return services;
        }

        /// <summary>
        /// Scans an assembly for command handlers and registers them automatically.
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <param name="assembly">The assembly to scan for command handlers</param>
        /// <returns>The service collection for method chaining</returns>
        public static IServiceCollection AddCommandHandlersFromAssembly(this IServiceCollection services, System.Reflection.Assembly assembly)
        {
            var handlerTypes = assembly.GetTypes()
                .Where(type => !type.IsAbstract && !type.IsInterface)
                .Where(type => IsCommandHandler(type))
                .ToArray();

            return services.AddCommandHandlers(handlerTypes);
        }

        /// <summary>
        /// Determines whether a type is a command handler.
        /// </summary>
        /// <param name="type">The type to check</param>
        /// <returns>True if the type is a command handler, false otherwise</returns>
        private static bool IsCommandHandler(Type type)
        {
            var baseType = type.BaseType;
            while (baseType != null)
            {
                if (baseType.IsGenericType && baseType.GetGenericTypeDefinition() == typeof(CommandHandler<>))
                {
                    return true;
                }
                baseType = baseType.BaseType;
            }
            return false;
        }
    }
}