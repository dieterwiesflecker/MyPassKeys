using Fido2NetLib;
using Fido2NetLib.Objects;

namespace MyPassKeys;

public class Fido2Service(IFido2Factory fido2Factory)
{
    /// <summary>
    /// Create options for browser
    /// </summary>
    /// <param name="user"></param>
    /// <param name="existingKeys"></param>
    /// <returns></returns>
    public async Task<CredentialCreateOptions> CreateOptionsAsync(Fido2User user, IReadOnlyList<PublicKeyCredentialDescriptor> existingKeys)
    {
        var fido2 = await fido2Factory.CreateAsync();
        return fido2.RequestNewCredential(new RequestNewCredentialParams
        {
            User = user,
            ExcludeCredentials = existingKeys,
            AuthenticatorSelection = AuthenticatorSelection.Default,
            AttestationPreference = AttestationConveyancePreference.Direct,
            Extensions = new AuthenticationExtensionsClientInputs
            {
                Extensions = true,
                CredProps = true  // New extension support
            }
        });
    }

    public async Task<RegisteredPublicKeyCredential> CompleteRegistrationAsync(
        AuthenticatorAttestationRawResponse response,
        CredentialCreateOptions options,
        IsCredentialIdUniqueToUserAsyncDelegate callback)
    {
        var fido2 = await fido2Factory.CreateAsync();
        return await fido2.MakeNewCredentialAsync(new MakeNewCredentialParams
        {
            AttestationResponse = response,
            OriginalOptions = options,
            IsCredentialIdUniqueToUserCallback = callback
        });
    }

    public async Task<AssertionOptions> BeginAuthenticationAsync(IReadOnlyList<PublicKeyCredentialDescriptor> allowedCredentials)
    {
        var fido2 = await fido2Factory.CreateAsync();
        return fido2.GetAssertionOptions(new GetAssertionOptionsParams
        {
            AllowedCredentials = allowedCredentials,
            UserVerification = UserVerificationRequirement.Preferred,
            Extensions = new AuthenticationExtensionsClientInputs { Extensions = true }
        });
    }

    public async Task<VerifyAssertionResult> CompleteAuthenticationAsync(
        AuthenticatorAssertionRawResponse response,
        AssertionOptions options,
        byte[] publicKey,
        uint counter,
        IsUserHandleOwnerOfCredentialIdAsync callback)
    {
        var fido2 = await fido2Factory.CreateAsync();
        return await fido2.MakeAssertionAsync(new MakeAssertionParams
        {
            AssertionResponse = response,
            OriginalOptions = options,
            StoredPublicKey = publicKey,
            StoredSignatureCounter = counter,
            IsUserHandleOwnerOfCredentialIdCallback = callback
        });
    }
}
