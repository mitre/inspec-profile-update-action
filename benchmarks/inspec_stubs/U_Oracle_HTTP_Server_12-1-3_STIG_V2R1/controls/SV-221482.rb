control 'SV-221482' do
  title 'OHS must have the SSLVerifyClient directive set within each SSL-enabled VirtualHost directive to perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLVerifyClient" directive at the OHS server, virtual host, and/or directory configuration scopes.

3. If this directive is omitted or set improperly, this is a finding.'
  desc 'fix', '1. Open every .conf file (e.g., ssl.conf) included in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor that requires an SSL-enabled "<VirtualHost>" directive.

2. Search for the "SSLVerifyClient" directive at the OHS server, virtual host, and/or directory configuration scope.

3. Set the "SSLVerifyClient" directive to "require", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23197r415129_chk'
  tag severity: 'medium'
  tag gid: 'V-221482'
  tag rid: 'SV-221482r415131_rule'
  tag stig_id: 'OH12-1X-000248'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-23186r415130_fix'
  tag 'documentable'
  tag legacy: ['SV-78913', 'V-64423']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
