control 'SV-224777' do
  title 'The ISEC7 EMM Suite must use FIPS-validated SHA-2 or higher hash function for digital signature generation and verification (non-legacy use).'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

To protect the integrity of the authenticator and authentication mechanism used for the cryptographic module used by the network device, the application, operating system, or protocol must be configured to use one of the following hash functions for hashing the password or other authenticator in accordance with SP 800-131Ar1: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA3-224, SHA3-256, SHA3-384, and SHA3-512.

For digital signature verification, SP800-131Ar1 allows SHA-1 for legacy use where needed.'
  desc 'check', 'Log in to the ISEC7 EMM Console.
Confirm that the browser session is secured using a DoD issued certificate.

Alternately, Log in to the ISEC7 EMM Console.
Navigate to Administration >> Configuration >> Apache Tomcat Settings.
Identify which type of Keystore is being used.

Windows MY:  
    Open the Microsoft Management Console.
    Add the Certificates Snap-In for the ISEC7 Service Account.
    Navigate to the Personal Certificates Store.
    Verify the certificate is issued by a DoD Trusted Certificate Authority.

JavaKeystore PKCS12:
    Using a Keystore browser such as Portecle, open the ISEC7 EMM Suite keystore.
    Enter the Keystore password when prompted.
    Open the installed certificate and verify it was issued by a DoD Trusted Certificate Authority.

If certificates used by the server are not DoD issued certificates, this is a finding.'
  desc 'fix', 'Submit a CSR for a DoD Issued Certificate with the private key.
Retrieve the approved certificate from the issuing Certificate Authority.
Set the friendly name on the certificate to https.

Windows-MY:
    Open the Microsoft Management Console.
    Add the Certificates Snap-In for the ISEC7 Service Account.
    Navigate to the Personal Certificates Store.
    Import the certificate with Private key.
    Log in to the ISEC7 EMM Console.
    Navigate to Administration >> Configuration >> Apache Tomcat Settings.
    Set the Keystore Type to Windows-MY.

JavaKeystore:
    Using a Keystore browser such as Portecle, open the ISEC7 EMM Suite keystore.
    Enter the Keystore password when prompted.
    Delete the self-signed certificate in the keystore.
    Import the DoD issued certificate with the private key.
    Enter the key password when prompted.
    Enter the certificate alias as https when prompted.
    Save the keystore with the same keystore password.
    Log in to the ISEC7 EMM Console.
    Navigate to Administration >> Configuration >> Apache Tomcat Settings.
    Verify the Keystore type is set to JavaKeystore PKCS12.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26468r461587_chk'
  tag severity: 'medium'
  tag gid: 'V-224777'
  tag rid: 'SV-224777r505933_rule'
  tag stig_id: 'ISEC-06-002660'
  tag gtitle: 'SRG-APP-000610'
  tag fix_id: 'F-26456r461588_fix'
  tag 'documentable'
  tag legacy: ['SV-106507', 'V-97403']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
