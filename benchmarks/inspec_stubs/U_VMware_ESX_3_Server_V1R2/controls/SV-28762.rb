control 'SV-28762' do
  title 'The SSH daemon must use a FIPS 140-2 validated cryptographic module (operating in FIPS mode).'
  desc 'Cryptographic modules used by the system must be validated by the NIST CVMP as compliant with FIPS 140-2. Cryptography performed by modules not validated is viewed by NIST as providing no protection for the data.'
  desc 'check', 'Determine if the SSH daemon uses a FIPS 140-2 validated cryptographic module (operating in FIPS mode).  If it does not, this is a finding.'
  desc 'fix', 'Configure the SSH daemon to use a FIPS 140-2 validated cryptographic module (operating in FIPS mode).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29150r1_chk'
  tag severity: 'medium'
  tag gid: 'V-23826'
  tag rid: 'SV-28762r1_rule'
  tag stig_id: 'GEN005490'
  tag gtitle: 'GEN005490'
  tag fix_id: 'F-26161r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-001145']
  tag nist: ['SC-13 (1)']
end
