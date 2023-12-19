control 'SV-221488' do
  title 'OHS must have the SSLEngine, SSLProtocol, and SSLWallet directives enabled to meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting stored data.'
  desc 'Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The web server must provide FIPS-compliant encryption modules when storing encrypted data and configuration settings.'
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
3b. Set the "SSLProtocol" directive to "TLSv1.2”; add the directive if it does not exist.

4a. Search for the "SSLWallet" directive at the OHS server configuration, virtual host, and/or directory levels.
4b. Set the "SSLWallet" directive to the location (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) of the Oracle wallet created via orapki with AES Encryption (-compat_v12 parameters) that contains only the identity certificate for the host and DoD Certificate Authorities; add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23203r881053_chk'
  tag severity: 'medium'
  tag gid: 'V-221488'
  tag rid: 'SV-221488r881055_rule'
  tag stig_id: 'OH12-1X-000255'
  tag gtitle: 'SRG-APP-000179-WSR-000110'
  tag fix_id: 'F-23192r881054_fix'
  tag 'documentable'
  tag legacy: ['SV-78925', 'V-64435']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
