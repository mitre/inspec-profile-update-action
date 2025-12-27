control 'SV-214286' do
  title 'The Apache web server must perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity, and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', %q(In a command line, run "httpd -M | grep -i ssl_module". 
 
If the "ssl_module" is not enabled, this is a finding. 
 
Determine the location of the "HTTPD_ROOT" directory and the "ssl.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
 
Review <'HTTPD_ROOT'>/conf.d/ssl.conf 
 
Verify "SSLVerifyClient" is set to "require": 
  
SSLVerifyClient require 
  
Verify "SSLVerifyDepth" is set to a number greater than "0": 
  
SSLVerifyDepth 1 
  
If "SSLVerifyClient" is not set to "require" or "SSLVerifyDepth" is not set to a number greater than "0", this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "ssl.conf" file: 
 
# httpd -V | egrep -i 'httpd_root|server_config_file' 
-D HTTPD_ROOT="/etc/httpd" 
 
Edit <'HTTPD_ROOT'>/conf.d/ssl.conf 
  
Set "SSLVerifyClient" to "require".  
  
Set "SSLVerifyDepth" to "1". 
  
SSLVerifyDepth 1 
  
For more information: https://httpd.apache.org/docs/current/mod/ssl_module.html)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15499r277199_chk'
  tag severity: 'medium'
  tag gid: 'V-214286'
  tag rid: 'SV-214286r612241_rule'
  tag stig_id: 'AS24-U2-000380'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-15497r277200_fix'
  tag 'documentable'
  tag legacy: ['SV-102873', 'V-92785']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
