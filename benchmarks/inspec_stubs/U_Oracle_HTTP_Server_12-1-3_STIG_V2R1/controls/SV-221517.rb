control 'SV-221517' do
  title 'OHS must have the SSLVerifyClient directive enabled to only accept client certificates issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLVerifyClient" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. If this directive is omitted or is not set to "require", this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLVerifyClient" directive at the OHS server, virtual host, and/or directory configuration scope.

3. Set the "SSLVerifyClient" directive to "require", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23232r415230_chk'
  tag severity: 'medium'
  tag gid: 'V-221517'
  tag rid: 'SV-221517r415232_rule'
  tag stig_id: 'OH12-1X-000302'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-23221r415231_fix'
  tag 'documentable'
  tag legacy: ['SV-79015', 'V-64525']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
