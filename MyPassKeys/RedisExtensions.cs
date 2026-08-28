using System.Text.Json;
using StackExchange.Redis;

namespace MyPassKeys;

public static class RedisExtensions
{
    public static async Task<T?> GetOrCreateAsync<T>(
        this IDatabase db,
        string key,
        Func<Task<T?>> factory,
        TimeSpan? expiry = null)
    {
        var cached = await db.StringGetAsync(key);
        if (cached.HasValue)
        {
            return JsonSerializer.Deserialize<T>(cached.ToString());
        }

        var result = await factory();

        if (result is not null)
        {
            await db.StringSetAsync(key, JsonSerializer.Serialize(result), expiry ?? TimeSpan.FromMinutes(5));
            //await db.StringSetAsync(key, JsonSerializer.Serialize(tenant), TimeSpan.FromMinutes(5));

        }

        return result;
    }
}