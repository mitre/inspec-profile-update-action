control 'SV-214370' do
  title 'The Apache web server must perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file to determine if the "SSLVerifyClient" and "SSLVerifyDepth" directives exist and look like the following.

If they do not, this is a finding.

SSLVerifyClient require

SSLVerifyDepth 1 

If "SSLVerifyDepth" is set to "0", this is a finding.)
  desc 'fix', 'Ensure that client verification is enabled. For each enabled hosted application on the server, enable and set "SSLVerifyClient" to "require" and ensure that the server is configured to verify the client certificate by enabling "SSLVerifyDepth".
 
Example:
 
SSLVerifyClient require
 
Find the line "SSLVerifyDepth" and ensure it is set properly:
 
SSLVerifyDepth 1
 
"SSLVerifyDepth" is set based on the number of CAs that are required in the certificate chain to check, before the client certificate is accepted as valid. A setting of "0" would allow self-signed CAs to validate client certificates, which is not desirable in this context.

Additional Information:

https://httpd.apache.org/docs/current/mod/mod_ssl.html'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15581r505098_chk'
  tag severity: 'medium'
  tag gid: 'V-214370'
  tag rid: 'SV-214370r505100_rule'
  tag stig_id: 'AS24-W2-000380'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-15579r505099_fix'
  tag 'documentable'
  tag legacy: ['SV-102605', 'V-92517']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
