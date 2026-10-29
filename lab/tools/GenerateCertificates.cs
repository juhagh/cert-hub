using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

string outputDirectory;

try
{
    outputDirectory = Path.GetFullPath(args[0]);
    Console.WriteLine($"Path provided: {outputDirectory}");
}
catch (IOException ex)
{
    Console.Error.WriteLine($"Failed to construct output directory path: {ex.Message}");
    return 1;
}
catch (UnauthorizedAccessException ex)
{
    Console.Error.WriteLine($"Failed to construct output directory path: {ex.Message}");
    return 1;
}
catch (ArgumentException ex)
{
    Console.Error.WriteLine($"Failed to construct output directory path: {ex.Message}");
    return 1;
}

if (Path.Exists(outputDirectory))
{
    Console.Error.WriteLine($"The output directory {outputDirectory} already exists. Please move or rename it or provide alternative path.");
    return 1;
}

var parentDirectory = Directory.GetParent(outputDirectory);
if (parentDirectory is null || !parentDirectory.Exists)
{
    Console.Error.WriteLine("Parent directory of output directory does not exist or is null.");
    return 1;
}

var stagingDirectory = Path.Combine(parentDirectory.FullName , $".certhub-generation-{Guid.NewGuid():N}");

Console.WriteLine($"\nStaging Directory: {stagingDirectory}");

if (Console.IsInputRedirected)
{
    Console.Error.WriteLine("Console input is redirected, please use interactive mode instead.");
    return 1;
}

bool pfxPasswordOk = TryReadConfirmedPassword(
    prompt: "\nPlease enter PFX bundle password. It will be used for client and server PFX bundles: ",
    confirmationPrompt: "Please confirm PFX bundle password: ",
    password: out string pfxPassword);
    
if (!pfxPasswordOk)
{
    return 1;
}

Console.WriteLine("\nPFX password confirmed.");

bool keyPasswordOk = TryReadConfirmedPassword(
    prompt: "\nPlease enter private key password. This password will protect standalone CA, server and client PEM keys: ",
    confirmationPrompt: "Please confirm private key password: ",
    password: out string keyPassword);
    
if (!keyPasswordOk)
{
    return 1;
}

Console.WriteLine("\nPrivate key password confirmed.");

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

Console.WriteLine("\nCA Root certificate:");
Console.WriteLine($"\nSubject: {caCertificate.Subject}," +
                  $"\nIssuer: {caCertificate.Issuer}," +
                  $"\nNotBefore: {caCertificate.NotBefore.ToUniversalTime():O}," +
                  $"\nNotAfter: {caCertificate.NotAfter.ToUniversalTime():O}");

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

var serverEnhancedKeyUsageExtension = new X509EnhancedKeyUsageExtension(
    enhancedKeyUsages: new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, // Server authentication
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
serverRequest.CertificateExtensions.Add(serverEnhancedKeyUsageExtension);
serverRequest.CertificateExtensions.Add(sanExtension);
serverRequest.CertificateExtensions.Add(serverSubjectKeyIdentifierExtension);
serverRequest.CertificateExtensions.Add(serverAuthorityKeyIdentifierExtension);

byte[] serverSerial = RandomNumberGenerator.GetBytes(16);
serverSerial[0] = 1;

using var issuedServerCertificate = serverRequest.Create(
    issuerCertificate: caCertificate,
    notBefore: serverNotBefore,
    notAfter: serverNotAfter,
    serialNumber: serverSerial);

using var serverCertificate = issuedServerCertificate.CopyWithPrivateKey(serverKey);

Console.WriteLine("\nValid server certificate:");
Console.WriteLine($"\nSubject:{serverCertificate.Subject}" +
                  $"\nIssuer: {serverCertificate.Issuer}" +
                  $"\nNotBefore: {serverCertificate.NotBefore.ToUniversalTime():O}" +
                  $"\nNotAfter: {serverCertificate.NotAfter.ToUniversalTime():O}" +
                  $"\nHasPrivateKey: {serverCertificate.HasPrivateKey}");

byte[] expiredServerSerial = RandomNumberGenerator.GetBytes(16);
expiredServerSerial[0] = 1;

using var issuedExpiredServerCertificate = serverRequest.Create(
    issuerCertificate: caCertificate,
    notBefore: expiredNotBefore,
    notAfter: expiredNotAfter,
    serialNumber: expiredServerSerial);

using var expiredServerCertificate = issuedExpiredServerCertificate.CopyWithPrivateKey(serverKey);
Console.WriteLine("\nExpired server certificate:");
Console.WriteLine($"\nSubject:{expiredServerCertificate.Subject}" +
                  $"\nIssuer: {expiredServerCertificate.Issuer}" +
                  $"\nNotBefore: {expiredServerCertificate.NotBefore.ToUniversalTime():O}" +
                  $"\nNotAfter: {expiredServerCertificate.NotAfter.ToUniversalTime():O}" +
                  $"\nHasPrivateKey: {expiredServerCertificate.HasPrivateKey}");

// Create Client key and request
using var clientKey = RSA.Create(3072);

var clientRequest = new CertificateRequest(
    subjectName: "CN=CertHub Lab Client",
    key: clientKey,
    hashAlgorithm: HashAlgorithmName.SHA256,
    padding: RSASignaturePadding.Pkcs1
);

var clientBasicConstraints = new X509BasicConstraintsExtension(
    certificateAuthority: false,
    hasPathLengthConstraint: false,
    pathLengthConstraint: 0,
    critical: true);

var clientKeyUsageExtension = new X509KeyUsageExtension(
    keyUsages: X509KeyUsageFlags.DigitalSignature,
    critical: true);

var clientEnhancedKeyUsageExtension = new X509EnhancedKeyUsageExtension(
    enhancedKeyUsages: new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, // 1.3.6.1.5.5.7.3.2 Client Authentication
    critical: false);

var clientSubjectKeyIdentifierExtension = new X509SubjectKeyIdentifierExtension(
    key: clientRequest.PublicKey, 
    critical: false);

var clientAuthorityKeyIdentifierExtension =
    X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifierExtension);

clientRequest.CertificateExtensions.Add(clientBasicConstraints);
clientRequest.CertificateExtensions.Add(clientKeyUsageExtension);
clientRequest.CertificateExtensions.Add(clientEnhancedKeyUsageExtension);
clientRequest.CertificateExtensions.Add(clientSubjectKeyIdentifierExtension);
clientRequest.CertificateExtensions.Add(clientAuthorityKeyIdentifierExtension);

byte[] clientSerial = RandomNumberGenerator.GetBytes(16);
clientSerial[0] = 1;

using var issuedClientCertificate = clientRequest.Create(
    issuerCertificate: caCertificate,
    notBefore: serverNotBefore,
    notAfter: serverNotAfter,
    serialNumber: clientSerial);

using var clientCertificate = issuedClientCertificate.CopyWithPrivateKey(clientKey);

Console.WriteLine("\nClient certificate:");
Console.WriteLine($"\nSubject:{clientCertificate.Subject}" +
                  $"\nIssuer: {clientCertificate.Issuer}" +
                  $"\nNotBefore: {clientCertificate.NotBefore.ToUniversalTime():O}" +
                  $"\nNotAfter: {clientCertificate.NotAfter.ToUniversalTime():O}" +
                  $"\nHasPrivateKey: {clientCertificate.HasPrivateKey}");

var exportParameters = new PbeParameters(
    encryptionAlgorithm: PbeEncryptionAlgorithm.Aes256Cbc,
    hashAlgorithm: HashAlgorithmName.SHA256,
    iterationCount: 100_000);

var serverPfx = serverCertificate.ExportPkcs12(exportParameters, pfxPassword);
var expiredServerPfx = expiredServerCertificate.ExportPkcs12(exportParameters, pfxPassword);
var clientPfx = clientCertificate.ExportPkcs12(exportParameters, pfxPassword);

Console.WriteLine($"\nServerPfxBundleLength: {serverPfx.Length}");
Console.WriteLine($"\nExpiredServerPfxBundleLength: {expiredServerPfx.Length}");
Console.WriteLine($"\nClientPfxBundleLength: {clientPfx.Length}");

Console.WriteLine("Validating Client PFX.");
bool clientPfxIsValid = TryVerifyPfxExport(
    pfxBytes: clientPfx,
    password: pfxPassword,
    originalCertificate: clientCertificate);

if (!clientPfxIsValid)
{
    return 1;
}

Console.WriteLine("Validating Server PFX.");
bool serverPfxIsValid = TryVerifyPfxExport(
    pfxBytes: serverPfx,
    password: pfxPassword,
    originalCertificate: serverCertificate);

if (!serverPfxIsValid)
{
    return 1;
}

Console.WriteLine("Validating Expired Server PFX.");
bool expiredServerPfxIsValid = TryVerifyPfxExport(
    pfxBytes: expiredServerPfx,
    password: pfxPassword,
    originalCertificate: expiredServerCertificate);

if (!expiredServerPfxIsValid)
{
    return 1;
}

Console.WriteLine("\nAll PFX bundles verified.");

// Export PEM encoded certificate
var caCertificatePem = caCertificate.ExportCertificatePem();
var serverCertificatePem = serverCertificate.ExportCertificatePem();
var expiredServerCertificatePem = expiredServerCertificate.ExportCertificatePem();
var clientCertificatePem = clientCertificate.ExportCertificatePem();
var serverCsrPem = serverRequest.CreateSigningRequestPem();

var caKeyPem = caKey.ExportEncryptedPkcs8PrivateKeyPem(keyPassword, exportParameters);
var serverKeyPem = serverKey.ExportEncryptedPkcs8PrivateKeyPem(keyPassword, exportParameters);
var clientKeyPem = clientKey.ExportEncryptedPkcs8PrivateKeyPem(keyPassword, exportParameters);

using var tempCaRsaKey = RSA.Create();
tempCaRsaKey.ImportFromEncryptedPem(input: caKeyPem, password: keyPassword);

using var tempServerRsaKey = RSA.Create();
tempServerRsaKey.ImportFromEncryptedPem(input: serverKeyPem, password: keyPassword);

using var tempClientRsaKey = RSA.Create();
tempClientRsaKey.ImportFromEncryptedPem(input: clientKeyPem, password: keyPassword);

if (!tempCaRsaKey.ExportSubjectPublicKeyInfo().SequenceEqual(caKey.ExportSubjectPublicKeyInfo()))
{
    Console.Error.WriteLine("CA key SubjectPublicKeyInfo does not match the original key.");
    return 1;
}

if (!tempServerRsaKey.ExportSubjectPublicKeyInfo().SequenceEqual(serverKey.ExportSubjectPublicKeyInfo()))
{
    Console.Error.WriteLine("Server key SubjectPublicKeyInfo does not match the original key.");
    return 1;
}

if (!tempClientRsaKey.ExportSubjectPublicKeyInfo().SequenceEqual(clientKey.ExportSubjectPublicKeyInfo()))
{
    Console.Error.WriteLine("Client key SubjectPublicKeyInfo does not match the original key.");
    return 1;
}

Console.WriteLine("All encrypted private-key exports verified.");

bool stagingCreated = false;
try
{
    if (Path.Exists(stagingDirectory))
    {
        Console.Error.WriteLine("Staging path already exists; refusing to reuse it.");
        return 1;
    }

    if (OperatingSystem.IsWindows())
    {
        Directory.CreateDirectory(stagingDirectory);
        stagingCreated = true;
        Console.WriteLine($"Staging directory: {stagingDirectory} created successfully.");
    }
    else if (OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
    {
        var unixFileMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
        Directory.CreateDirectory(stagingDirectory, unixFileMode);
        stagingCreated = true;
        Console.WriteLine($"Staging directory: {stagingDirectory} created successfully.");
    }
    else
    {
        Console.Error.WriteLine("Unsupported operating system.");
        return 1;
    }

    WriteNewFile(Path.Combine(stagingDirectory, "certhub-lab-root-ca.cert.pem"),
        Encoding.UTF8.GetBytes(caCertificatePem), true);
    WriteNewFile(Path.Combine(stagingDirectory, "certhub-lab-root-ca.key.pem"), Encoding.UTF8.GetBytes(caKeyPem),
        false);
    WriteNewFile(Path.Combine(stagingDirectory, "localhost.cert.pem"), Encoding.UTF8.GetBytes(serverCertificatePem),
        false);
    WriteNewFile(Path.Combine(stagingDirectory, "localhost-expired.cert.pem"),
        Encoding.UTF8.GetBytes(expiredServerCertificatePem), false);
    WriteNewFile(Path.Combine(stagingDirectory, "localhost.key.pem"), Encoding.UTF8.GetBytes(serverKeyPem), false);
    WriteNewFile(Path.Combine(stagingDirectory, "localhost.csr.pem"), Encoding.UTF8.GetBytes(serverCsrPem), false);
    WriteNewFile(Path.Combine(stagingDirectory, "localhost.pfx"), serverPfx, true);
    WriteNewFile(Path.Combine(stagingDirectory, "localhost-expired.pfx"), expiredServerPfx, true);
    WriteNewFile(Path.Combine(stagingDirectory, "client.cert.pem"), Encoding.UTF8.GetBytes(clientCertificatePem), false);
    WriteNewFile(Path.Combine(stagingDirectory, "client.key.pem"), Encoding.UTF8.GetBytes(clientKeyPem), false);
    WriteNewFile(Path.Combine(stagingDirectory, "client.pfx"), clientPfx, false);

    if (OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
    {
        var containerReadableMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead |
                                    UnixFileMode.OtherRead;
        File.SetUnixFileMode(Path.Combine(stagingDirectory, "localhost.pfx"), containerReadableMode);
        File.SetUnixFileMode(Path.Combine(stagingDirectory, "localhost-expired.pfx"), containerReadableMode);
        File.SetUnixFileMode(Path.Combine(stagingDirectory, "certhub-lab-root-ca.cert.pem"), containerReadableMode);
    }
    
    Directory.Move(sourceDirName: stagingDirectory, destDirName: outputDirectory);
    stagingCreated = false;

    Console.WriteLine($"Certificate files are created and can be found from: {outputDirectory}");
}
catch (IOException ex)
{
    Console.Error.WriteLine($"Failed to create certificate output: {ex.Message}");
    return 1;
}
catch (UnauthorizedAccessException ex)
{
    Console.Error.WriteLine($"Failed to create certificate output: {ex.Message}");
    return 1;
}
finally
{
    try
    {
        if (stagingCreated && Path.Exists(stagingDirectory))
        {
            Directory.Delete(stagingDirectory, recursive: true);
        }
    }
    catch (IOException ex)
    {
        Console.Error.WriteLine($"Failed to clean up staging directory: {stagingDirectory}. Error: {ex.Message}");
    }
    catch (UnauthorizedAccessException ex)
    {
        Console.Error.WriteLine($"Failed to clean up staging directory: {stagingDirectory}. Error: {ex.Message}");
    }
}


bool TryReadConfirmedPassword(string prompt, string confirmationPrompt, out string password)
{
    password = ReadPassword(prompt);
    string passwordConfirmation = ReadPassword(confirmationPrompt);
    
    if (string.IsNullOrWhiteSpace(password))
    {
        Console.Error.WriteLine("Password cannot be empty.");
        password = string.Empty;
        return false;
    }

    if (!string.Equals(password, passwordConfirmation, StringComparison.Ordinal))
    {
        Console.Error.WriteLine("Passwords do not match.");
        password = string.Empty;
        return false;
    }

    return true;
}

string ReadPassword(string prompt)
{
    var sb = new StringBuilder();
    ConsoleKeyInfo consoleKey;
    
    Console.Write(prompt);
    do
    {
        consoleKey = Console.ReadKey(intercept: true);
        if (!char.IsControl(consoleKey.KeyChar))
        {
            sb.Append(consoleKey.KeyChar);
        }

        if (consoleKey.Key == ConsoleKey.Backspace && sb.Length > 0)
        {
            sb.Remove(sb.Length - 1, 1);
        }
    } while (consoleKey.Key != ConsoleKey.Enter);

    Console.WriteLine();

    return sb.ToString();
}

bool TryVerifyPfxExport(byte[] pfxBytes, string password, X509Certificate2 originalCertificate)
{
    X509KeyStorageFlags keyStorageFlags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
    
    using var pkcs12Cert = X509CertificateLoader.LoadPkcs12(pfxBytes, password, keyStorageFlags);
    if (!pkcs12Cert.HasPrivateKey)
    {
        Console.Error.WriteLine("PFX is missing private key.");
        return false;
    }

    if (originalCertificate.GetCertHashString(HashAlgorithmName.SHA256) != pkcs12Cert.GetCertHashString(HashAlgorithmName.SHA256))
    {
        Console.Error.WriteLine("Certificate fingerprints do not match.");
        return false;
    }

    return true;
}

void WriteNewFile(string path, byte[] contents, bool containerReadable)
{
    var options = new FileStreamOptions
    {
        Mode = FileMode.CreateNew,
        Access = FileAccess.Write,
        Share = FileShare.None
    };

    if (OperatingSystem.IsMacOS() || OperatingSystem.IsLinux())
    {
        if (containerReadable)
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead;
        }
        else
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
    }
    
    using var fs = new FileStream(path, options);
    fs.Write(contents);
}

return 0;