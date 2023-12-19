control 'SV-79011' do
  title 'OHS must have the SSLEngine, SSLProtocol, and SSLWallet directives enabled so SSL requests can be processed with client certificates only issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', '1. As required, open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.
Note: Does not apply to admin.conf.

2. Search for the following directive at the OHS server, virtual host, and/or directory configuration scopes:
"SSLEngine"
"SSLProtocol"
"SSLWallet"

3. If any of these directives are omitted, this is a finding.

4. If "SSLEngine" is not set to on or "SSLProtocol" is not set to TLS versions 1.1 and greater, this is a finding.5. Validate that the folder specified in the "SSLWallet" directive exists. If the folder does not exist or contain a valid wallet, this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.
Note: Does not apply to admin.conf.
2a. Search for the "SSLEngine" directive at the OHS server, virtual host, and/or directory configuration scopes.
2b. Set the "SSLEngine" directive to "On", add the directive if it does not exist.
3a. Search for the "SSLProtocol" directive at the OHS server configuration, virtual host, and/or directory levels.
3b. Set the "SSLProtocol" directive to "TLSv1.2 TLSv1.1", add the directive if it does not exist.
4a. Search for the "SSLWallet" directive at the OHS server configuration, virtual host, and/or directory levels.
4b. Set the "SSLWallet" directive to the location (i.e., folder within $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/keystores) of the Oracle wallet created via orapki with AES Encryption (-compat_v12 parameters) that contains only the identity certificate for the host and DoD Certificate Authorities, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65273r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64521'
  tag rid: 'SV-79011r2_rule'
  tag stig_id: 'OH12-1X-000300'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-70451r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
