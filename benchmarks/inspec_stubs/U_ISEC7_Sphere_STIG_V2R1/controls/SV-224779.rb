control 'SV-224779' do
  title 'The ISEC7 EMM Suite must use a FIPS 140-2-validated cryptographic module to implement encryption services for unclassified information requiring confidentiality, generate cryptographic hashes, and to configure web management tools with FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to protect the confidentiality of maintenance and diagnostic communications for nonlocal maintenance sessions.'
  desc 'FIPS 140-2 precludes the use of invalidated cryptography for the cryptographic protection of sensitive or valuable data within Federal systems. Unvalidated cryptography is viewed by NIST as providing no protection to the information or data. In effect, the data would be considered unprotected plaintext. If the agency specifies that the information or data be cryptographically protected, then FIPS 140-2 is applicable. In essence, if cryptography is required, it must be validated. Cryptographic modules that have been approved for classified use may be used in lieu of modules that have been validated against the FIPS 140-2 standard. 

The cryptographic module used must have one FIPS-validated encryption algorithm (i.e., validated Advanced Encryption Standard [AES]). This validated algorithm must be used for encryption for cryptographic security function within the product being evaluated.

EMM Suite is using the standard JCE module coming with OpenJDK 11 (included in installer) or Oracle JRE either legacy 1.8 or latest release.
see https://openjdk.java.net/groups/security/   There are two module providers, IBM and RSA. The check/fix are written assuming the RSA module is used.
Any FIPS 140-2 compliant JCE module (.jar) can be replaced and configured and used with EMM Suite.'
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
  desc 'fix', 'Login to the ISEC7 EMM Suite Monitor server.
Browse to the Java Install\\Lib\\Security.
Edit the Java.Security file.
Add the following entries in bold to the Java.Security file:

security.provider.1=com.rsa.jsafe.provider.JsafeJCE
security.provider.2=sun.security.provider.Sun
security.provider.3=sun.security.rsa.SunRsaSign
security.provider.4=sun.security.ec.SunEC
security.provider.5=com.sun.net.ssl.internal.ssl.Provider JsafeJCE
security.provider.6=com.sun.crypto.provider.SunJCE
security.provider.7=sun.security.jgss.SunProvider
security.provider.8=com.sun.security.sasl.Provider
security.provider.9=org.jcp.xml.dsig.internal.dom.XMLDSigRI
security.provider.10=sun.security.smartcardio.SunPCSC
security.provider.11=sun.security.mscapi.SunMSCAPI
com.rsa.cryptoj.jce.kat.strategy=on.load
com.rsa.cryptoj.jce.fips140initialmode=FIPS140_SSL'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26470r461593_chk'
  tag severity: 'medium'
  tag gid: 'V-224779'
  tag rid: 'SV-224779r505933_rule'
  tag stig_id: 'ISEC-06-002700'
  tag gtitle: 'SRG-APP-000635'
  tag fix_id: 'F-26458r461594_fix'
  tag 'documentable'
  tag legacy: ['SV-106509', 'V-97405']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
