using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace MyPassKeys;

public class EmailService(
    IHttpClientFactory httpClientFactory,
    IConfiguration configuration,
    ILogger<EmailService> logger)
{
    public async Task<bool> SendVerificationCodeAsync(string toEmail, string code, string tenantName)
    {
        var apiKey = configuration["Resend:ApiKey"];
        if (string.IsNullOrEmpty(apiKey))
        {
            logger.LogError("Resend API key is not configured");
            return false;
        }

        var fromEmail = configuration["Resend:FromEmail"] ?? "noreply@resend.dev";

        var payload = new
        {
            from = $"{tenantName} <{fromEmail}>",
            to = new[] { toEmail },
            subject = $"Your verification code: {code}",
            html = $"""
                    <div style="font-family: sans-serif; max-width: 400px; margin: 0 auto; padding: 20px;">
                        <h2>Email Verification</h2>
                        <p>Your verification code is:</p>
                        <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; text-align: center;
                                    padding: 20px; background: #f4f4f4; border-radius: 8px; margin: 20px 0;">
                            {code}
                        </div>
                        <p style="color: #666; font-size: 14px;">This code expires in 10 minutes.</p>
                    </div>
                    """
        };

        var client = httpClientFactory.CreateClient();
        var request = new HttpRequestMessage(HttpMethod.Post, "https://api.resend.com/emails")
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

        try
        {
            var response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();
                logger.LogError("Resend API error: {StatusCode} {Body}", response.StatusCode, body);
                return false;
            }

            logger.LogInformation("Verification email sent to {Email}", toEmail);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to send verification email to {Email}", toEmail);
            return false;
        }
    }
}
