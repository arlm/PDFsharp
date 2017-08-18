using CommandLine;
using CommandLine.Text;

namespace ExtractSecurityParameters
{
    class Options
    {
        [Option('i', "in", Required = true, HelpText = "Input file to be processed.")]
        public string InputFile { get; set; }

        [Option('o', "out", Required = false, DefaultValue =  "CryptoParams.cs", HelpText = "Output file to be processed.")]
        public string OutputFile { get; set; }

        [Option("verbose", DefaultValue = false, HelpText = "Prints all messages to standard output.")]
        public bool Verbose { get; set; }

        [ParserState]
        public IParserState LastParserState { get; set; }

        [HelpOption]
        public string GetUsage()
        {
            return HelpText.AutoBuild(this, (HelpText current) => HelpText.DefaultParsingErrorsHandler(this, current));
        }
    }
}
