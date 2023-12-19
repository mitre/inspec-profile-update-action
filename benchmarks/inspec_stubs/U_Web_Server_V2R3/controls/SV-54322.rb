control 'SV-54322' do
  title 'The web server must use cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance when encrypting stored data.'
  desc 'Encryption is only as good as the encryption modules utilized.  Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

FIPS 140-2 is the current standard for validating cryptographic modules and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The web server must provide FIPS-compliant encryption modules when storing encrypted data and configuration settings.'
  desc 'check', 'Review web server documentation and deployed configuration to determine whether the encryption modules utilized for storage of data are FIPS 140-2 compliant.

Reference the following NIST site to identify validated encryption modules: 

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the encryption modules used for storage of data are not FIPS 140-2 validated, this is a finding.'
  desc 'fix', 'Configure the web server to utilize FIPS 140-2 approved encryption modules when the web server is storing data.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48142r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41745'
  tag rid: 'SV-54322r3_rule'
  tag stig_id: 'SRG-APP-000179-WSR-000110'
  tag gtitle: 'SRG-APP-000179-WSR-000110'
  tag fix_id: 'F-47204r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
