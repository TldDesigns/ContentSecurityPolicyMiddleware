using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using System.Web;
using System.IO;
using HtmlAgilityPack;
using System.Security.Cryptography;

namespace TLDDesigns.Owin.ContentSecurityPolicy
{
    public class ContentSecurityPolicy : OwinMiddleware
    {
        private readonly ContentSecurityPolicyOptions _options;
        public ContentSecurityPolicy(OwinMiddleware next, ContentSecurityPolicyOptions options) : base(next)
        {
            _options = options;
        }

        public async override Task Invoke(IOwinContext context)
        {
            using (var stream = context.Response.Body)

            {
                using (var buffer = new MemoryStream())
                {
                    context.Response.Body = buffer;
                                        
                    HttpResponse httpResponse = HttpContext.Current.Response;

                    OutputCaptureStream outputCapture = new OutputCaptureStream(httpResponse.Filter);

                    httpResponse.Filter = outputCapture;
                                        
                    if (_options.Script.UseNonce || _options.Style.UseNonce)
                    {
                        _options.Nonce = createNonce();
                        context.Set<string>(_options.Nonce, "ScriptNonce");
                    }

                    addCspHeaders(context, _options);

                    await Next.Invoke(context);

                    string currentNonce = _options.Nonce;

                    var isHtml = context.Response.ContentType?.ToLower().Contains("text/html");
                    if (context.Response.StatusCode == 200 && isHtml.GetValueOrDefault())
                    {

                        var capturedStream = outputCapture.CapturedData;

                        capturedStream.Seek(0, SeekOrigin.Begin);

                        using (var reader = new StreamReader(capturedStream))
                        {
                            string responseBody = await reader.ReadToEndAsync();

                            if (responseBody != "")
                            {

                                string domSelector;

                                HtmlDocument responsePage = new HtmlDocument();

                                capturedStream.Seek(0, SeekOrigin.Begin);

                                responsePage.Load(capturedStream);

                                domSelector = "//*[@data-nonceSecret]";

                                if (_options.Script.UseNonce)
                                {
                                    domSelector += " | //script";
                                }

                                if (_options.Style.UseNonce)
                                {
                                    domSelector += " | //style | //link[@as='style'] | //link[@rel='stylesheet']";
                                }

                                HtmlNodeCollection nodeCollection = responsePage.DocumentNode.SelectNodes(domSelector);

                                if (nodeCollection != null)
                                {
                                    foreach (HtmlNode currentNode in nodeCollection)
                                    {
                                        if (_options.NonceSecret != null)
                                        {
                                            if (currentNode.GetAttributeValue("data-nonceSecret", null) == _options.NonceSecret)
                                            {
                                                if (_options.Script.UseNonce)
                                                {
                                                    if (currentNode.Name == "script")
                                                    {

                                                        currentNode.SetAttributeValue("nonce", currentNonce);
                                                    }
                                                }
                                                if (_options.Style.UseNonce)
                                                {
                                                    if (currentNode.Name == "link" || currentNode.Name == "style")
                                                    {

                                                        currentNode.SetAttributeValue("nonce", currentNonce);
                                                    }
                                                }
                                            }

                                        }
                                        else
                                        {
                                            if (_options.Script.UseNonce)
                                            {
                                                if (currentNode.Name == "script")
                                                {

                                                    currentNode.SetAttributeValue("nonce", currentNonce);
                                                }
                                            }
                                            if (_options.Style.UseNonce)
                                            {
                                                if (currentNode.Name == "link" || currentNode.Name == "style")
                                                {

                                                    currentNode.SetAttributeValue("nonce", currentNonce);
                                                }
                                            }
                                        }

                                        if (currentNode.Attributes.Contains("data-nonceSecret"))
                                        {
                                            currentNode.Attributes["data-nonceSecret"].Remove();
                                        }
                                    }

                                }
                                                                
                                MemoryStream newOutputStream = new MemoryStream();

                                httpResponse.Clear();

                                responsePage.Save(newOutputStream);

                                newOutputStream.Seek(0, SeekOrigin.Begin);

                                newOutputStream.CopyTo(stream);

                            }
                        }
                    }
                }
            }
        }

        private void logDebugMessage(IOwinContext context, string msg)
        {
            var currentStage = HttpContext.Current.CurrentNotification;
            context.Get<TextWriter>("host.TraceOutput").WriteLine("Owin CSP Nonce Debug Stage: " + currentStage + " Msg: " + msg);
        }

        private string createNonce()
        {
            var rng = new RNGCryptoServiceProvider();
            var nonceBytes = new byte[32];
            rng.GetBytes(nonceBytes);
            var nonce = Convert.ToBase64String(nonceBytes);

            return nonce;
        }

        private void addCspHeaders(IOwinContext context, ContentSecurityPolicyOptions options)
        {

            string requestHost = context.Request.Uri.Host;

            if (options.EnforceOnLocalhost == true || requestHost != "localhost")
            {
                context.Response.Headers.Add(options.Header, new[] { options.Directive });
            }
        }

        internal class OutputCaptureStream : Stream
        {
            private Stream InnerStream;
            public MemoryStream CapturedData { get; private set; }

            public OutputCaptureStream(Stream inner)
            {
                InnerStream = inner;
                CapturedData = new MemoryStream();
            }

            public override bool CanRead
            {
                get { return InnerStream.CanRead; }
            }

            public override bool CanSeek
            {
                get { return InnerStream.CanSeek; }
            }

            public override bool CanWrite
            {
                get { return InnerStream.CanWrite; }
            }

            public override void Flush()
            {
                //InnerStream.Flush();
            }

            public override long Length
            {
                get { return InnerStream.Length; }
            }

            public override long Position
            {
                get { return InnerStream.Position; }
                set { CapturedData.Position = InnerStream.Position = value; }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return InnerStream.Read(buffer, offset, count);
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                CapturedData.Seek(offset, origin);
                return InnerStream.Seek(offset, origin);
            }

            public override void SetLength(long value)
            {
                CapturedData.SetLength(value);
                InnerStream.SetLength(value);
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                CapturedData.Write(buffer, offset, count);
                InnerStream.Write(buffer, offset, count);
            }

        }
    }
}