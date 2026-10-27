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
                  $"\n\nserverNotBefore:  {serverNotBefore:O}" +
                  $"\nserverNotAfter:   {serverNotAfter:O}" +
                  $"\n\nexpiredNotBefore: {expiredNotBefore:O}" +
                  $"\nexpiredNotAfter:  {expiredNotAfter:O}");

// Create Root CA Certificate
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

// Create Server key and request
using var serverKey = RSA.Create(3072);

var serverRequest = new CertificateRequest(
    subjectName: "CN=localhost",
    key: serverKey,
    hashAlgorithm: HashAlgorithmName.SHA256,
    padding: RSASignaturePadding.Pkcs1
);

var serverBasicConstraints = new X509BasicConstraintsExtension(
    certificateAuthority: false,
    hasPathLengthConstraint: false,
    pathLengthConstraint: 0,
    critical: true);

var serverKeyUsageExtension = new X509KeyUsageExtension(
    keyUsages: X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
    critical: true);

var enhancedKeyUsageExtension = new X509EnhancedKeyUsageExtension(
    enhancedKeyUsages: new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, 
    critical: false);

var sanBuilder = new SubjectAlternativeNameBuilder();
sanBuilder.AddDnsName("localhost");
var sanExtension = sanBuilder.Build();

var serverSubjectKeyIdentifierExtension = new X509SubjectKeyIdentifierExtension(
    key: serverRequest.PublicKey, 
    critical: false);

var serverAuthorityKeyIdentifierExtension =
    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifierExtension);

serverRequest.CertificateExtensions.Add(serverBasicConstraints);
serverRequest.CertificateExtensions.Add(serverKeyUsageExtension);
serverRequest.CertificateExtensions.Add(enhancedKeyUsageExtension);
serverRequest.CertificateExtensions.Add(sanExtension);
serverRequest.CertificateExtensions.Add(serverSubjectKeyIdentifierExtension);
serverRequest.CertificateExtensions.Add(serverAuthorityKeyIdentifierExtension);

byte[] serial = RandomNumberGenerator.GetBytes(16);
serial[0] = 1;

using var issuedServerCertificate = serverRequest.Create(
    issuerCertificate: caCertificate,
    notBefore: serverNotBefore,
    notAfter: serverNotAfter,
    serialNumber: serial);

using var serverCertificate = issuedServerCertificate.CopyWithPrivateKey(serverKey);

Console.WriteLine("\nValid server certificate:");
Console.WriteLine($"\nSubject:{serverCertificate.Subject}" +
                  $"\nIssuer: {serverCertificate.Issuer}" +
                  $"\nNotBefore: {serverCertificate.NotBefore.ToUniversalTime():O}" +
                  $"\nNotAfter: {serverCertificate.NotAfter.ToUniversalTime():O}" +
                  $"\nHasPrivateKey: {serverCertificate.HasPrivateKey}");

byte[] expiredSerial = RandomNumberGenerator.GetBytes(16);
expiredSerial[0] = 1;

using var issuedExpiredServerCertificate = serverRequest.Create(
    issuerCertificate: caCertificate,
    notBefore: expiredNotBefore,
    notAfter: expiredNotAfter,
    serialNumber: expiredSerial);

using var expiredServerCertificate = issuedExpiredServerCertificate.CopyWithPrivateKey(serverKey);
Console.WriteLine("\nExpired server certificate:");
Console.WriteLine($"\nSubject:{expiredServerCertificate.Subject}" +
                  $"\nIssuer: {expiredServerCertificate.Issuer}" +
                  $"\nNotBefore: {expiredServerCertificate.NotBefore.ToUniversalTime():O}" +
                  $"\nNotAfter: {expiredServerCertificate.NotAfter.ToUniversalTime():O}" +
                  $"\nHasPrivateKey: {expiredServerCertificate.HasPrivateKey}");

Console.WriteLine("\nCA Root certificate:");
Console.WriteLine($"\nSubject: {caCertificate.Subject}," +
                  $"\nIssuer: {caCertificate.Issuer}," +
                  $"\nNotBefore: {caCertificate.NotBefore.ToUniversalTime():O}," +
                  $"\nNotAfter: {caCertificate.NotAfter.ToUniversalTime():O}");

return 0;