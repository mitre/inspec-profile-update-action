control 'SV-36740' do
  title 'A private web server must utilize an approved TLS version.'
  desc 'Transport Layer Security (TLS) encryption is a required security setting for a private web server.  Encryption of private information is essential to ensuring data confidentiality.  If private information is not encrypted, it can be intercepted and easily read by an unauthorized party.  A private web server must use a FIPS 140-2 approved TLS version, and all non-FIPS-approved SSL versions must be disabled.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Open the httpd.conf file.

Search for an uncommented LoadModule ssl_module directive statement.

If this statement is found commented, this is a finding.

After determining that the ssl module is active search for the following uncommented directives: SSLProtocol & SSLEngine

For all enabled SSLProtocol directives ensure they are set to “TLSv1”. If the SSLProtocol directive is not set to TLSv1, this is a finding.

For all enabled SSLEngine directives ensure they are set to “on”.

Both the SSLProtocol and SSLEngine directives must be set correctly or this is a finding.

NOTE: In some cases web servers are configured in an environment to support load balancing. This configuration most likely utilizes a content switch to control traffic to the various web servers. In this situation, the TLS certificate for the web sites may be installed on the content switch vs, the individual web sites. This solution is acceptable as long as the web servers are isolated from the general population LAN. We do not want users to have the ability to bypass the content switch to access the web sites.'
  desc 'fix', 'Edit the httpd.conf file to load the ssl_module; set the SSLProtocol to TLSv1; and set the SSLEngine to On.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-35818r3_chk'
  tag severity: 'medium'
  tag gid: 'V-2262'
  tag rid: 'SV-36740r2_rule'
  tag stig_id: 'WG340 W20'
  tag gtitle: 'WG340'
  tag fix_id: 'F-31059r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
