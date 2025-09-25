namespace S7.Core.Abstractions.Factories
{
    /// <summary>
    /// Abstract factory interface for creating families of related objects.
    /// </summary>
    /// <typeparam name="T">The type of objects this factory creates.</typeparam>
    public interface IAbstractFactory<out T>
    {
        /// <summary>
        /// Creates an instance of the specified type.
        /// </summary>
        /// <returns>A new instance of type T.</returns>
        T Create();
    }

    /// <summary>
    /// Abstract factory interface for creating families of related objects with parameters.
    /// </summary>
    /// <typeparam name="T">The type of objects this factory creates.</typeparam>
    /// <typeparam name="TParam">The type of parameter required for creation.</typeparam>
    public interface IAbstractFactory<out T, in TParam>
    {
        /// <summary>
        /// Creates an instance of the specified type with the given parameter.
        /// </summary>
        /// <param name="parameter">The parameter required for creation.</param>
        /// <returns>A new instance of type T.</returns>
        T Create(TParam parameter);
    }

    /// <summary>
    /// Abstract factory interface for creating families of related objects with multiple parameters.
    /// </summary>
    /// <typeparam name="T">The type of objects this factory creates.</typeparam>
    /// <typeparam name="TParam1">The type of the first parameter.</typeparam>
    /// <typeparam name="TParam2">The type of the second parameter.</typeparam>
    public interface IAbstractFactory<out T, in TParam1, in TParam2>
    {
        /// <summary>
        /// Creates an instance of the specified type with the given parameters.
        /// </summary>
        /// <param name="parameter1">The first parameter required for creation.</param>
        /// <param name="parameter2">The second parameter required for creation.</param>
        /// <returns>A new instance of type T.</returns>
        T Create(TParam1 parameter1, TParam2 parameter2);
    }
}