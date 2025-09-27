using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Services;
using S7.Core.Commands.Handlers;
using S7.Core.Commands.Services;

namespace S7.Core.Commands.Extensions
{
    /// <summary>
    /// Extension methods for registering command services with dependency injection.
    /// </summary>
    public static class CommandServiceExtensions
    {
        /// <summary>
        /// Adds command handlers to the service collection.
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The service collection for chaining</returns>
        public static IServiceCollection AddCommandHandlers(this IServiceCollection services)
        {
            // Register the handlers directly for the new architecture
            services.AddTransient<MemoryDumpCommandHandler>();
            services.AddTransient<StagerInstallCommandHandler>();

            return services;
        }

        /// <summary>
        /// Adds power controller services to the service collection.
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The service collection for chaining</returns>
        public static IServiceCollection AddPowerController(this IServiceCollection services)
        {
            // Register power controller services
            services.AddSingleton<ModbusConnectionManager>();
            services.AddSingleton<IPowerController, ModbusPowerController>();

            return services;
        }

        /// <summary>
        /// Adds all command-related services to the service collection.
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <returns>The service collection for chaining</returns>
        public static IServiceCollection AddCommandServices(this IServiceCollection services)
        {
            services.AddCommandHandlers();
            services.AddPowerController();

            return services;
        }

        /// <summary>
        /// Configures command services with custom options.
        /// </summary>
        /// <param name="services">The service collection</param>
        /// <param name="configureOptions">Action to configure command options</param>
        /// <returns>The service collection for chaining</returns>
        public static IServiceCollection AddCommandServices(
            this IServiceCollection services, 
            Action<CommandServiceOptions> configureOptions)
        {
            var options = new CommandServiceOptions();
            configureOptions(options);

            if (options.IncludeCommandHandlers)
            {
                services.AddCommandHandlers();
            }

            if (options.IncludePowerController)
            {
                services.AddPowerController();
            }

            return services;
        }
    }

    /// <summary>
    /// Configuration options for command services.
    /// </summary>
    public class CommandServiceOptions
    {
        /// <summary>
        /// Gets or sets a value indicating whether to include command handlers.
        /// </summary>
        public bool IncludeCommandHandlers { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether to include power controller services.
        /// </summary>
        public bool IncludePowerController { get; set; } = true;
    }
}