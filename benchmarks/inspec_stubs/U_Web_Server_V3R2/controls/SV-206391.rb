control 'SV-206391' do
  title 'The web server must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules. 

The web server must provide FIPS-compliant encryption modules when authenticating users and processes.'
  desc 'check', 'Review web server documentation and deployed configuration to determine whether the encryption modules utilized for authentication are FIPS 140-2 compliant.  Reference the following NIST site to identify validated encryption modules: http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the encryption modules used for authentication are not FIPS 140-2 validated, this is a finding.'
  desc 'fix', 'Configure the web server to utilize FIPS 140-2 approved encryption modules when authenticating users and processes.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6652r377765_chk'
  tag severity: 'medium'
  tag gid: 'V-206391'
  tag rid: 'SV-206391r879616_rule'
  tag stig_id: 'SRG-APP-000179-WSR-000111'
  tag gtitle: 'SRG-APP-000179'
  tag fix_id: 'F-6652r377766_fix'
  tag 'documentable'
  tag legacy: ['SV-54323', 'V-41746']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
