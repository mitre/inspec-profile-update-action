control 'SV-221479' do
  title 'OHS must use FIPS modules to perform RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses."
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23194r415120_chk'
  tag severity: 'medium'
  tag gid: 'V-221479'
  tag rid: 'SV-221479r415122_rule'
  tag stig_id: 'OH12-1X-000245'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-23183r415121_fix'
  tag 'documentable'
  tag legacy: ['SV-78907', 'V-64417']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
