using System;
using System.Collections.Generic;

namespace TLDDesigns.Owin.ContentSecurityPolicy
{
    public class ContentSecurityPolicyOptions
    {


        public class SandboxOptions
        {
            protected readonly string _Self = "'self'";
            protected readonly string _UnsafeInline = "'unsafe-inline'";
            protected readonly string _UnsafeEval = "'unsafe-eval'";
            protected readonly string _Directive;
            protected readonly string _NonceDirective = "'nonce-";
            protected readonly string _StrictDynamic = "'strict-dynamic'";

            public List<string> Sources = new List<string>();

            public SandboxOptions(string Directive)
            {
                _Directive = Directive;

            }

            internal string _addToSources(string allSources, string source)
            {
                if (allSources != String.Empty)
                {
                    if (source != String.Empty)
                    {
                        allSources += " " + source;
                    }
                }
                else
                {
                    allSources = source;
                }

                return allSources;
            }

            public override string ToString()
            {
                string sources = String.Empty;
                //string output = String.Empty;

                //string sourcesString = String.Join(" ", Sources);

                //_allSources = _addToSources(_allSources, sourcesString);

                //if (_allSources != String.Empty)
                //{
                //    output = _Directive + " " + _allSources + ";";
                //}

                //_allSources = String.Empty;

                return ToString(sources);

            }

            public virtual string ToString(string existingSources)
            {

                string output = String.Empty;

                string sourcesString = String.Join(" ", Sources);

                output = _addToSources(existingSources, sourcesString);

                if (output != String.Empty)
                {
                    output = _Directive + " " + output + ";";
                }


                return output;
            }

        }

        public class SourceOptions : SandboxOptions
        {

            public bool UseSelf { get; set; }

            public SourceOptions(string Directive) : base(Directive)
            {
                UseSelf = false;
            }

            //public override string ToString()
            //{
            //    if (UseSelf)
            //    { 
            //        _allSources = _addToSources(_allSources, _Self);

            //    }

            //    return base.ToString();
            //}

            public override string ToString(string existingSources)
            {
                string output = String.Empty;

                if (UseSelf)
                {
                    output = _addToSources(existingSources, _Self);
                }
                else
                {
                    output = existingSources;
                }

                return base.ToString(output);
            }
        }



        public class StyleOptions : SourceOptions
        {

            public bool UseUnsafeInline { get; set; }
            public bool UseNonce { get; set; }
            internal string _Nonce { get; set; }
            internal string _NonceSecret { get; set; }

            public StyleOptions(string Directive) : base(Directive)
            {
                UseUnsafeInline = false;
                UseNonce = false;
            }
            //public override string ToString()
            //{
            //    if (UseUnsafeInline)
            //    {
            //        _allSources = _addToSources(_allSources, _UnsafeInline);
            //    }

            //    if (UseNonce)
            //    {
            //        _allSources = _addToSources(_allSources, _NonceDirective + _Nonce + "'");


            //    }


            //    return base.ToString();
            //}

            public override string ToString(string existingSources)
            {
                string output = String.Empty;

                if (UseUnsafeInline)
                {
                    output = _addToSources(existingSources, _UnsafeInline);
                }
                else
                {
                    output = existingSources;
                }

                if (UseNonce)
                {
                    output = _addToSources(output, _NonceDirective + _Nonce + "'");
                }

                return base.ToString(output);
            }
        }

        public class ScriptOptions : StyleOptions
        {

            public bool UseStrictDynamic { get; set; }

            public bool UseUnsafeEval { get; set; }

            public ScriptOptions(string Directive) : base(Directive)
            {
                UseUnsafeEval = false;
                UseStrictDynamic = false;
            }

            //public override string ToString()
            //{
            //    if (UseUnsafeEval)
            //    {
            //        _allSources = _addToSources(_allSources, _UnsafeEval);

            //    }

            //    //return _allSources;// _Nonce;

            //    return base.ToString();
            //}
            public override string ToString(string existingSources)
            {
                string output = String.Empty;

                if (UseUnsafeEval)
                {
                    output = _addToSources(existingSources, _UnsafeEval);
                }
                else
                {
                    output = existingSources;
                }

                if (UseStrictDynamic)
                {
                    output = _addToSources(output, _StrictDynamic);
                }

                return base.ToString(output);
            }

        }

        public SourceOptions Default = new SourceOptions("default-src");

        public ScriptOptions Script = new ScriptOptions("script-src");

        public StyleOptions Style = new StyleOptions("style-src");

        public SourceOptions Image = new SourceOptions("img-src");

        public SourceOptions Connect = new SourceOptions("connect-src");

        public SourceOptions Font = new SourceOptions("font-src");

        public SourceOptions Object = new SourceOptions("object-src");

        public SourceOptions Media = new SourceOptions("media-src");

        public SandboxOptions Sandbox = new SandboxOptions("sandbox");

        public string Directive
        {
            get
            {
                string fullDirective = String.Empty;

                string report = String.Empty;

                if (ReportUri != string.Empty)
                {

                    report = Sandbox._addToSources(_ReportDirective, ReportUri + ";");

                }

                fullDirective = Sandbox._addToSources(fullDirective, Default.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Script.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Style.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Image.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Connect.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Font.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Media.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Sandbox.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, Sandbox.ToString());

                fullDirective = Sandbox._addToSources(fullDirective, report);

                return fullDirective;
            }
        }

        public string Header
        {
            get
            {
                string returnHeader = String.Empty;
                if (ReportOnly)
                {
                    returnHeader = "Content-Security-Policy-Report-Only";
                }
                else
                {
                    returnHeader = "Content-Security-Policy";
                }
                return returnHeader;
            }
        }

        protected string _Nonce;

        protected string _NonceSecret;

        protected string _ReportDirective = "report-uri";

        //public bool UseScriptNonce { get; set; }
        //public bool UseStyleNonce { get; set; }
        public string Nonce
        {
            get
            {
                return _Nonce;
            }

            set
            {
                _Nonce = value;
                Style._Nonce = value;
                Script._Nonce = value;

            }
        }

        public string NonceSecret
        {
            get
            {
                return _NonceSecret;
            }
            set
            {
                _NonceSecret = value;
                Style._NonceSecret = value;
                Script._NonceSecret = value;
            }
        }

        public string ReportOnlyUri { get; set; }

        public string EnforceUri { get; set; }

        public bool ReportOnly { get; set; }

        public bool EnforceOnLocalhost { get; set; }


        public string ReportUri
        {
            get
            {
                if (ReportOnly)
                {
                    return ReportOnlyUri;
                }
                else
                {
                    return EnforceUri;
                }
            }
        }

        public ContentSecurityPolicyOptions()
        {
            ReportOnlyUri = string.Empty;
            EnforceUri = string.Empty;
            //UseScriptNonce = false;
            //UseStyleNonce = false;
            Nonce = string.Empty;
            EnforceOnLocalhost = true;
        }

    }
}