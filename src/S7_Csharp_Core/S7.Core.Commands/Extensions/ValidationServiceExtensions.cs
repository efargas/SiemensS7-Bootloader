using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using S7.Core.Abstractions.Commands;
using S7.Core.Abstractions.Middleware;
using S7.Services.Middleware;

namespace S7.Core.Commands.Extensions
{
    /// <summary>
    /// Extension methods for registering validation services and middleware.
    /// </summary>
    public static class ValidationServiceExtensions
    {
        /// <summary>
        /// Registers validation pipeline and default middleware components.
        /// </summary>
        /// <param name="services">The service collection to register services with.</param>
        /// <returns>The service collection for method chaining.</returns>
        public static IServiceCollection AddValidationPipeline(this IServiceCollection services)
        {
            // Register validation pipeline
            services.AddSingleton<IValidationPipeline, ValidationPipeline>();

            // Register default middleware components
            services.AddTransient(typeof(DataAnnotationsValidationMiddleware<>));
            services.AddTransient(typeof(BusinessRuleValidationMiddleware<>));

            return services;
        }

        /// <summary>
        /// Configures validation middleware for specific command options types.
        /// </summary>
        /// <param name="host">The host to configure validation for.</param>
        /// <returns>The host for method chaining.</returns>
        public static IHost ConfigureValidationMiddleware(this IHost host)
        {
            var validationPipeline = host.Services.GetRequiredService<IValidationPipeline>();

            // Register middleware for MemoryDumpOptions
            var memoryDumpDataAnnotationsMiddleware = host.Services.GetRequiredService<DataAnnotationsValidationMiddleware<MemoryDumpOptions>>();
            var memoryDumpBusinessRuleMiddleware = host.Services.GetRequiredService<BusinessRuleValidationMiddleware<MemoryDumpOptions>>();
            
            validationPipeline.RegisterMiddleware(memoryDumpDataAnnotationsMiddleware);
            validationPipeline.RegisterMiddleware(memoryDumpBusinessRuleMiddleware);

            // Register middleware for StagerInstallOptions
            var stagerInstallDataAnnotationsMiddleware = host.Services.GetRequiredService<DataAnnotationsValidationMiddleware<StagerInstallOptions>>();
            var stagerInstallBusinessRuleMiddleware = host.Services.GetRequiredService<BusinessRuleValidationMiddleware<StagerInstallOptions>>();
            
            validationPipeline.RegisterMiddleware(stagerInstallDataAnnotationsMiddleware);
            validationPipeline.RegisterMiddleware(stagerInstallBusinessRuleMiddleware);

            return host;
        }

        /// <summary>
        /// Registers a custom validation middleware for a specific command options type.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options.</typeparam>
        /// <typeparam name="TMiddleware">The type of validation middleware.</typeparam>
        /// <param name="services">The service collection to register the middleware with.</param>
        /// <returns>The service collection for method chaining.</returns>
        public static IServiceCollection AddValidationMiddleware<TOptions, TMiddleware>(this IServiceCollection services)
            where TOptions : CommandHandlerOptions
            where TMiddleware : class, IValidationMiddleware<TOptions>
        {
            services.AddTransient<TMiddleware>();
            return services;
        }

        /// <summary>
        /// Registers a custom validation middleware instance for a specific command options type.
        /// </summary>
        /// <typeparam name="TOptions">The type of command options.</typeparam>
        /// <param name="host">The host to register the middleware with.</param>
        /// <param name="middleware">The validation middleware instance to register.</param>
        /// <returns>The host for method chaining.</returns>
        public static IHost RegisterValidationMiddleware<TOptions>(this IHost host, IValidationMiddleware<TOptions> middleware)
            where TOptions : CommandHandlerOptions
        {
            var validationPipeline = host.Services.GetRequiredService<IValidationPipeline>();
            validationPipeline.RegisterMiddleware(middleware);
            return host;
        }
    }
}