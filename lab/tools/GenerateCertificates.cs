using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

Console.WriteLine("This is a script to create certificates necessary to run the CertHub Lab.\n");
if (args.Length != 1)
{
    Console.Error.WriteLine("Please provide exactly one argument for output directory.");
    Console.Error.WriteLine("\nExample: dotnet run --file lab/tools/GenerateCertificates.cs -- lab/certificates/generated");
    return 1;
}

if (string.IsNullOrWhiteSpace(args[0]))
{
    Console.Error.WriteLine("Output directory path cannot be empty.");
    return 1;
}

var outputDirectory = Path.GetFullPath(args[0]);
Console.WriteLine($"Path provided: {outputDirectory}");

if (Path.Exists(outputDirectory))
{
    Console.Error.WriteLine($"The output directory {outputDirectory} already exists. Please move or rename it or provide alternative path.");
    return 1;
}

var generationTime = DateTimeOffset.UtcNow;
var caNotBefore = generationTime.AddDays(-7);
var caNotAfter = generationTime.AddDays(365);
var serverNotBefore = generationTime.AddMinutes(-5);
var serverNotAfter = generationTime.AddDays(90);
var expiredNotBefore = generationTime.AddDays(-2);
var expiredNotAfter = generationTime.AddDays(-1);

Console.WriteLine($"generationTime:   {generationTime:O}" +
                  $"\ncaNotBefore:      {caNotBefore:O}" +
                  $"\ncaNotAfter:       {caNotAfter:O}" +
                  $"\nserverNotBefore:  {serverNotBefore:O}" +
                  $"\nserverNotAfter:   {serverNotAfter:O}" +
                  $"\nexpiredNotBefore: {expiredNotBefore:O}" +
                  $"\nexpiredNotAfter:  {expiredNotAfter:O}");

using var caKey = RSA.Create(3072);

// root-ca.ext.cnf equivalent
var caRequest = new CertificateRequest(
    subjectName: "CN=CertHub Lab Root CA",
    key: caKey,
    hashAlgorithm: HashAlgorithmName.SHA256,
    padding: RSASignaturePadding.Pkcs1);

var basicConstraintExtension = new X509BasicConstraintsExtension(
    certificateAuthority: true,
    hasPathLengthConstraint: true,
    pathLengthConstraint: 0,
    critical: true);

var keyUsageExtension = new X509KeyUsageExtension(
    keyUsages: X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign,
    critical: true);

var subjectKeyIdentifierExtension = new X509SubjectKeyIdentifierExtension(
    key: caRequest.PublicKey, 
    critical: false);

var authorityKeyIdentifierExtension =
    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifierExtension);

caRequest.CertificateExtensions.Add(basicConstraintExtension);
caRequest.CertificateExtensions.Add(keyUsageExtension);
caRequest.CertificateExtensions.Add(subjectKeyIdentifierExtension);
caRequest.CertificateExtensions.Add(authorityKeyIdentifierExtension);

using var caCertificate = caRequest.CreateSelfSigned(caNotBefore, caNotAfter);

Console.WriteLine($"\nSubject: {caCertificate.Subject}," +
                  $"\nIssuer: {caCertificate.Issuer}," +
                  $"\nNotBefore: {caCertificate.NotBefore.ToUniversalTime():O}," +
                  $"\nNotAfter: {caCertificate.NotAfter.ToUniversalTime():O}");

return 0;