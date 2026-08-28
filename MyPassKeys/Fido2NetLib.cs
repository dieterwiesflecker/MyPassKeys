using Fido2NetLib;

namespace MyPassKeys;

public interface IFido2Factory
{
  Task<IFido2> CreateAsync();
}