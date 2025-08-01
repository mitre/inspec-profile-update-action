control 'SV-36729' do
  title 'Public web servers must use TLS if authentication is required.'
  desc 'Transport Layer Security (TLS) is optional for a public web server.  However, if authentication is being performed, then the use of the TLS protocol is required.

Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure.  Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network.  To further protect the authentication data, the web server must use a FIPS 140-2 approved TLS version and all non-FIPS-approved SSL versions must be disabled.

FIPS 140-2 approved TLS versions include TLS V1.0 or greater.  NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', 'Open the httpd.conf file. 

Search for an uncommented LoadModule ssl_module directive statement.

If this statement is found commented (i.e. disabled), this is a finding.

Search the httpd.conf file for the following uncommented directives: SSLProtocol & SSLEngine

For all enabled SSLProtocol directives ensure they are set to “TLSv1”. If the SSLProtocol directive is not set to TLSv1, this is a finding.

For all enabled SSLEngine directives ensure they are set to “on”.

Both the SSLProtocol and SSLEngine directives must be set correctly or this is a finding

NOTE: In some cases web servers are configured in an environment to support load balancing. This configuration most likely utilizes a content switch to control traffic to the various web servers. In this situation, the TLS certificate for the web sites may be installed on the content switch versus the individual web sites. This solution is acceptable as long as the web servers are isolated from the general population LAN. We do not want users to have the ability to bypass the content switch to access the web sites.'
  desc 'fix', 'Edit the httpd.conf file to load the ssl_module; set the SSLProtocol to TLSv1; and set the SSLEngine to On.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-35808r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13694'
  tag rid: 'SV-36729r2_rule'
  tag stig_id: 'WG342 W20'
  tag gtitle: 'WG342'
  tag fix_id: 'F-31049r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCT-1, ECCT-2'
end
