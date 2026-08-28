namespace MyPassKeys;

public interface ITenantService
{
  Task<Tenant?> GetCurrentTenantAsync();
}