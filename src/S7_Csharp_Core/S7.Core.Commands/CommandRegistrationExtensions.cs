using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using S7.Net;
using System;

namespace S7.Core.Commands
{
    /// <summary>
    /// Extension methods for registering command handlers in the dependency injection container.
    /// </summary>
    public static class CommandRegistrationExtensions
    {
        /// <summary>
        /// Adds command handlers to the service collection.
        /// </summary>
        /// <param name="services">The service collection to add command handlers to</param>
        /// <returns>The service collection for method chaining</returns>
        /// <exception cref="ArgumentNullException">Thrown when services is null</exception>
        public static IServiceCollection AddCommandHandlers(this IServiceCollection services)
        {
            ArgumentNullException.ThrowIfNull(services);

            // Register command handlers as scoped services
            services.AddScoped<ICommandHandler<MemoryDumpOptions>, MemoryDumpCommandHandler>();
            services.AddScoped<ICommandHandler<StagerInstallOptions>, StagerInstallCommandHandler>();

            // Register the concrete command handler types for direct resolution if needed
            services.AddScoped<MemoryDumpCommandHandler>();
            services.AddScoped<StagerInstallCommandHandler>();

            return services;
        }

        /// <summary>
        /// Adds command handlers with their dependencies to the service collection.
        /// This method also registers common dependencies required by command handlers.
        /// </summary>
        /// <param name="services">The service collection to add command handlers to</param>
        /// <param name="payloadBasePath">The base path for payload files. If null, uses application base directory</param>
        /// <returns>The service collection for method chaining</returns>
        /// <exception cref="ArgumentNullException">Thrown when services is null</exception>
        public static IServiceCollection AddCommandHandlersWithDependencies(this IServiceCollection services, string? payloadBasePath = null)
        {
            ArgumentNullException.ThrowIfNull(services);

            // Register PayloadManager if not already registered
            services.AddSingleton<PayloadManager>(sp => 
                new PayloadManager(payloadBasePath ?? AppContext.BaseDirectory));

            // Add command handlers
            services.AddCommandHandlers();

            return services;
        }

        /// <summary>
        /// Sets up all registered command handlers by calling their SetupCommand methods.
        /// This should be called after the service container is built and the host is available.
        /// </summary>
        /// <param name="host">The host containing the configured service provider</param>
        /// <exception cref="ArgumentNullException">Thrown when host is null</exception>
        /// <exception cref="InvalidOperationException">Thrown when command setup fails</exception>
        public static void SetupAllCommandHandlers(this IHost host)
        {
            ArgumentNullException.ThrowIfNull(host);

            var logger = host.Services.GetService<ILogger<CommandRegistrationExtensions>>();
            
            try
            {
                logger?.LogInformation("Starting command handler setup");

                // Setup MemoryDumpCommandHandler
                try
                {
                    MemoryDumpCommandHandler.SetupCommand(host);
                    logger?.LogDebug("MemoryDumpCommandHandler setup completed");
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, "Failed to setup MemoryDumpCommandHandler");
                    throw new InvalidOperationException("Failed to setup MemoryDumpCommandHandler", ex);
                }

                // Setup StagerInstallCommandHandler
                try
                {
                    StagerInstallCommandHandler.SetupCommand(host);
                    logger?.LogDebug("StagerInstallCommandHandler setup completed");
                }
                catch (Exception ex)
                {
                    logger?.LogError(ex, "Failed to setup StagerInstallCommandHandler");
                    throw new InvalidOperationException("Failed to setup StagerInstallCommandHandler", ex);
                }

                logger?.LogInformation("All command handlers setup completed successfully");
            }
            catch (Exception ex)
            {
                logger?.LogError(ex, "Command handler setup failed");
                throw;
            }
        }

        /// <summary>
        /// Validates that all required services for command handlers are registered.
        /// </summary>
        /// <param name="services">The service collection to validate</param>
        /// <returns>True if all required services are registered, false otherwise</returns>
        /// <exception cref="ArgumentNullException">Thrown when services is null</exception>
        public static bool ValidateCommandHandlerServices(this IServiceCollection services)
        {
            ArgumentNullException.ThrowIfNull(services);

            // Build a temporary service provider to test service resolution
            using var serviceProvider = services.BuildServiceProvider();

            try
            {
                // Test that all required services can be resolved
                var memoryDumpHandler = serviceProvider.GetService<ICommandHandler<MemoryDumpOptions>>();
                var stagerInstallHandler = serviceProvider.GetService<ICommandHandler<StagerInstallOptions>>();
                var payloadManager = serviceProvider.GetService<PayloadManager>();

                return memoryDumpHandler != null && 
                       stagerInstallHandler != null && 
                       payloadManager != null;
            }
            catch
            {
                return false;
            }
        }
    }
}