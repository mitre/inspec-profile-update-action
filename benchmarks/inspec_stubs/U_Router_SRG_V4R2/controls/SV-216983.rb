control 'SV-216983' do
  title 'The BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Interview the ISSM and router administrator to determine if unique keys are being used. 

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure all eBGP routers with unique keys for each eBGP neighbor that it peers with.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-18213r382655_chk'
  tag severity: 'medium'
  tag gid: 'V-216983'
  tag rid: 'SV-216983r604135_rule'
  tag stig_id: 'SRG-NET-000230-RTR-000002'
  tag gtitle: 'SRG-NET-000230'
  tag fix_id: 'F-18211r382656_fix'
  tag 'documentable'
  tag legacy: ['V-78265', 'SV-92971']
  tag cci: ['CCI-002205', 'CCI-000366']
  tag nist: ['AC-4 (17)', 'CM-6 b']
end
