control 'SV-221534' do
  title 'OHS must have the SSLEngine, SSLProtocol, and SSLWallet directives enabled and configured to maintain the confidentiality and integrity of information during preparation for transmission.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

An example of this would be an SMTP queue. This queue may be added to a web server through an SMTP module to enhance error reporting or to allow developers to add SMTP functionality to their applications. 

Any modules used by the web server that queue data before transmission must maintain the confidentiality and integrity of the information before the data is transmitted.'
  desc 'check', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.
Note: Does not apply to admin.conf.

2. Search for the following directive at the OHS server, virtual host, and/or directory configuration scopes:
"SSLEngine"
"SSLProtocol"
"SSLWallet"

3. If any of these directives are omitted, this is a finding.

4. If "SSLEngine" is not set to "On" or "SSLProtocol" is not set to "TLS versions 1.1 and greater", this is a finding.

5. Validate that the folder specified in the "SSLWallet" directive exists. If the folder does not exist or contain a valid wallet, this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.
Note: Does not apply to admin.conf.
2a. Search for the "SSLEngine" directive at the OHS server, virtual host, and/or directory configuration scopes.
2b. Set the "SSLEngine" directive to "On", add the directive if it does not exist.
3a. Search for the "SSLProtocol" directive at the OHS server configuration, virtual host, and/or directory levels.
3b. Set the "SSLProtocol" directive to "TLSv1.2 TLSv1.1", add the directive if it does not exist.
4a. Search for the "SSLWallet" directive at the OHS server configuration, virtual host, and/or directory levels.
4b. Set the "SSLWallet" directive to the location (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) of the Oracle wallet created via orapki with AES Encryption (-compat_v12 parameters) that contains only the identity certificate for the host and DoD Certificate Authorities, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23249r415281_chk'
  tag severity: 'medium'
  tag gid: 'V-221534'
  tag rid: 'SV-221534r415283_rule'
  tag stig_id: 'OH12-1X-000326'
  tag gtitle: 'SRG-APP-000441-WSR-000181'
  tag fix_id: 'F-23238r415282_fix'
  tag 'documentable'
  tag legacy: ['SV-79059', 'V-64569']
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
