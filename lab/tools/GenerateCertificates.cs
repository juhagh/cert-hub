Console.WriteLine("This is a script to create certificates necessary to run the CertHub Lab.\n");
if (args.Length != 1)
{
    Console.Error.WriteLine("Please provide exactly one argument for output directory.");
    Console.Error.WriteLine("\nExample: dotnet run --file lab/tools/GenerateCertificates.cs -- lab/certificates/generated");
    return 1;
}

var outputDirectory = Path.GetFullPath(args[0]);

Console.WriteLine($"Path provided: {outputDirectory}");

return 0;