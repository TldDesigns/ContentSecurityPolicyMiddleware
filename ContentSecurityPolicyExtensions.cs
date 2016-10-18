using Owin;
using TLDDesigns.Owin.ContentSecurityPolicy;


public static class ContentSecurityPolicyExtensions
{
    public static void UseContentSecurityPolicy(this IAppBuilder app)
    {

        UseContentSecurityPolicy(app, new ContentSecurityPolicyOptions());    }

    public static void UseContentSecurityPolicy(this IAppBuilder app, ContentSecurityPolicyOptions options)
    {
        app.Use<ContentSecurityPolicy>(options);
    }
 
}
