control 'SV-224778' do
  title 'The ISEC7 EMM Suite must use a FIPS-validated cryptographic module to provision digital signatures.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard. 

The cryptographic module used must have one FIPS-validated encryption algorithm (i.e., validated Advanced Encryption Standard [AES]). This validated algorithm must be used for encryption for cryptographic security function within the product being evaluated.

EMM Suite is using the standard JCE module coming with OpenJDK 11 (included in installer) or Oracle JRE either legacy 1.8 or latest release (see https://openjdk.java.net/groups/security/). There are two module providers, IBM and RSA. The check/fix are written assuming the RSA module is used. Any FIPS 140-2 compliant JCE module (.jar) can be replaced and configured and used with EMM Suite.

'
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
  tag check_id: 'C-26469r461590_chk'
  tag severity: 'medium'
  tag gid: 'V-224778'
  tag rid: 'SV-224778r505933_rule'
  tag stig_id: 'ISEC-06-002690'
  tag gtitle: 'SRG-APP-000630'
  tag fix_id: 'F-26457r461591_fix'
  tag satisfies: ['SRG-APP-000630', 'SRG-APP-000412', 'SRG-APP-000514']
  tag 'documentable'
  tag legacy: ['SV-106517', 'V-97413']
  tag cci: ['CCI-002450', 'CCI-003123']
  tag nist: ['SC-13 b', 'MA-4 (6)']
end
