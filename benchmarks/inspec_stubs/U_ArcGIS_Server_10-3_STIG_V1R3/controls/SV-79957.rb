control 'SV-79957' do
  title 'The ArcGIS Server must use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity and DoD data may be compromised.

Applications utilizing encryption are required to use FIPS compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection thereby providing a degree of confidentiality. 

Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

'
  desc 'check', 'Review the ArcGIS for Server configuration to ensure the application uses mechanisms that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module. Substitute the target environment’s values for [bracketed] variables.

Navigate to [https://server.domain.com/arcgis]admin/system/handlers/rest/servicesdirectory (logon when prompted.)
Browse to “machines” >> [machine name] >> Click “edit”.
Verify that the name of the SSL certificate listed in the box for “Web server SSL Certificate” is not set to “SelfSignedCertificate”.

If the name of the SSL certificate listed in the box for “Web server SSL Certificate” is set to “SelfSignedCertificate”, this is a finding.

Browse to “security” >> “config”.
Verify “Protocol” parameter is not set to “HTTP Only”.
If the “Protocol” parameter is set to “HTTP Only”, this is a finding.

On the local system where the GIS Server is installed, open the “[C:\\Program Files\\]ArcGIS\\Server\\framework\\runtime\\tomcat\\conf\\server.xml” file.
Search for the parameter “ciphers=”.

Verify the property of the “ciphers=” parameter is set DoD-approved cipher suite value(s). A list of all possible values is located here: http://www.openssl.org/docs/apps/ciphers.html#CIPHER_SUITE_NAMES. An example of a valid configuration is provided below:

<Connector SSLEnabled="true" clientAuth="false" keyAlias=["MyValidCertificate"] keystoreFile=["C:\\arcgisserver\\config-store\\machines\\SERVER.DOMAIN.COM\\arcgis.keystore"] keystorePass="password" maxThreads="150" port="6443" protocol="org.apache.coyote.http11.Http11Protocol" scheme="https" secure="true" sslProtocol="TLS" ciphers="TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA"/>

If the “ciphers” parameter is not found, this is a finding.
If the “ciphers” parameter contains any non-DoD-approved ciphers, this is a finding.

On each GIS Server system and on each Web Adaptor system, Run the command “rsop” as Administrator on the Windows Command line.
Within the “Resultant Set of Policy” results, verify “Computer Configuration” >> “Windows Settings” >> “Security Settings” >> “Local Policies” >> “Security Options” >> “System cryptography: Use FIPS 140 compliant cryptographic algorithms, including encryption, hashing and signing algorithms” is set to “Enabled”.
If “System cryptography: Use FIPS 140 compliant cryptographic algorithms, including encryption, hashing and signing algorithms” not set to “Enabled”, this is a finding.

This control is not applicable for ArcGIS Servers which are deployed as part of a solution which ensures user web service traffic flows through third-party DoD compliant transport encryption devices (such as a load balancer that supports TLS encryption using DoD-approved certificates.)'
  desc 'fix', 'Configure the ArcGIS Server to use DoD-approved encryption certificates. Substitute the target environment’s values for [bracketed] variables. 

Using the Primary Site Administrator account, log on to the ArcGIS Server Administrator Directory at https://[server.domain.com]:6443/arcgis/admin. 

Navigate to machines >> [machine name] >> sslcertificates. Click "importRootOrIntermediate", then import a DoD-approved/provided root certificate file.

Click "importRootOrIntermediate", then import a DoD-approved/provided intermediate certificate file (if applicable.)

Click "importExistingServerCertificate", then import the SSL server certificate (public key) and private key pair.

In the "Certificate password" field, enter the password to unlock the file containing the SSL certificate.

In the "Alias" field, enter a unique name that easily identifies the certificate.

Click "Browse" to choose the .p12 or .pfx file that contains the SSL certificate and its private key.

Click "Import" to import the SSL certificate.

Browse to machines >> [machine name]. Click "edit".

Enter the alias of the SSL certificate (public/private key pair) that was chosen above in the box for "Web server SSL Certificate". Click "Save Edits" to apply the change.

Browse to security >> config >> update. Update the Protocol parameter to "HTTPS Only".

On the ArcGIS Server, open the "[C:\\Program Files\\]ArcGIS\\Server\\framework\\runtime\\tomcat\\conf\\server.xml" file.

Search the string <Connector SSLEnabled="true".

Within the "Connector" tag, add the following parameters (substitute DoD-approved ciphers for [bracketed] variables):

sslProtocol="TLS" ciphers="[DoD-approved cipher], [DoD-approved cipher], [DoD-approved cipher...]"

A list of all possible cipher values is located here: http://www.openssl.org/docs/apps/ciphers.html#CIPHER_SUITE_NAMES 

An example of a valid configuration is provided below:

<Connector SSLEnabled="true" 
clientAuth="false" 
keyAlias="MyValidCertificate" keystoreFile="C:\\arcgisserver\\config-store\\machines\\SERVER.DOMAIN.COM\\arcgis.keystore" keystorePass="password" 
maxThreads="150" port="6443" protocol="org.apache.coyote.http11.Http11Protocol" scheme="https" 
secure="true" 
sslProtocol="TLS" ciphers="TLS_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_RSA_WITH_AES_128_CBC_SHA, TLS_DHE_DSS_WITH_AES_128_CBC_SHA"/>

For each GIS Server system and each Web Adaptor system, apply the Local Policy or Group Policy:

Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "System cryptography: Use FIPS 140 compliant cryptographic algorithms, including encryption, hashing and signing algorithms" is set to "Enabled".'
  impact 0.7
  ref 'DPMS Target ArcGIS 10.3'
  tag check_id: 'C-66049r3_chk'
  tag severity: 'high'
  tag gid: 'V-65467'
  tag rid: 'SV-79957r2_rule'
  tag stig_id: 'AGIS-00-000081'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-71409r2_fix'
  tag satisfies: ['SRG-APP-000179', 'SRG-APP-000014', 'SRG-APP-000219', 'SRG-APP-000224']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-001184', 'CCI-001188']
  tag nist: ['AC-17 (2)', 'IA-7', 'SC-23', 'SC-23 (3)']
end
