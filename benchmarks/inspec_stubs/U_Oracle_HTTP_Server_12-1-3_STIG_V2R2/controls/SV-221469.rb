control 'SV-221469' do
  title 'A public OHS server must use TLS if authentication is required to host web sites.'
  desc 'Transport Layer Security (TLS) is optional for a public web server.  However, if authentication is being performed, then the use of the TLS protocol is required.

Without the use of TLS, the authentication data would be transmitted unencrypted and would become vulnerable to disclosure. Using TLS along with DoD PKI certificates for encryption of the authentication data protects the information from being accessed by all parties on the network. To further protect the authentication data, the web server must use a FIPS 140-2 approved TLS version and all non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 specifies the preferred configurations for government systems.'
  desc 'check', '1. As required, open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.
Note: Does not apply to admin.conf.

2. Search for the following directive at the OHS server, virtual host, and/or directory configuration scopes:
"SSLEngine"
"SSLProtocol"
"SSLWallet"

3. If any of these directives are omitted, this is a finding.

4. If "SSLEngine" is not set to "On", or "SSLProtocol" is not set to "TLSv1.2", this is a finding.

5. Validate that the folder specified in the "SSLWallet" directive exists. If the folder does not exist or contain a valid wallet, this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.
Note: Does not apply to admin.conf.

2a. Search for the "SSLEngine" directive at the OHS server, virtual host, and/or directory configuration scopes.
2b. Set the "SSLEngine" directive to "On"; add the directive if it does not exist.

3a. Search for the "SSLProtocol" directive at the OHS server configuration, virtual host, and/or directory levels.
3b. Set the "SSLProtocol" directive to "TLSv1.2"; add the directive if it does not exist.

4a. Search for the "SSLWallet" directive at the OHS server configuration, virtual host, and/or directory levels.
4b. Set the "SSLWallet" directive to the location (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) of the Oracle wallet created via orapki with AES Encryption (-compat_v12 parameters) that contains only the identity certificate for the host and DoD Certificate Authorities, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23184r881077_chk'
  tag severity: 'medium'
  tag gid: 'V-221469'
  tag rid: 'SV-221469r881079_rule'
  tag stig_id: 'OH12-1X-000232'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23173r881078_fix'
  tag 'documentable'
  tag legacy: ['SV-79191', 'V-64701']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
