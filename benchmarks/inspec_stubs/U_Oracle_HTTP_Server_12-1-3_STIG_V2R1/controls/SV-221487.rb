control 'SV-221487' do
  title 'OHS must have the SSLFIPS directive enabled to meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting stored data.'
  desc 'Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The web server must provide FIPS-compliant encryption modules when storing encrypted data and configuration settings.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23202r415144_chk'
  tag severity: 'medium'
  tag gid: 'V-221487'
  tag rid: 'SV-221487r415146_rule'
  tag stig_id: 'OH12-1X-000254'
  tag gtitle: 'SRG-APP-000179-WSR-000110'
  tag fix_id: 'F-23191r415145_fix'
  tag 'documentable'
  tag legacy: ['SV-78923', 'V-64433']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
