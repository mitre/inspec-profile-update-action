control 'SV-234240' do
  title 'The UEM Agent must use managed endpoint device key storage for all persistent secret and private keys.'
  desc 'If validated secure storage locations are not used for keys, they could be compromised.

'
  desc 'check', 'This requirement is not applicable if the UEM Agent is provided by the managed endpoint device operating system.

Verify the UEM Agent uses the managed endpoint device key storage for all persistent secret and private keys.

If the UEM Agent does not use the managed endpoint device key storage for all persistent secret and private keys, this is a finding.'
  desc 'fix', 'Configure the UEM Agent must use the managed endpoint device key storage for all persistent secret and private keys.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37425r612026_chk'
  tag severity: 'medium'
  tag gid: 'V-234240'
  tag rid: 'SV-234240r617354_rule'
  tag stig_id: 'SRG-APP-000176-UEM-100001'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-37390r612027_fix'
  tag satisfies: ['FCS_STG_EXT.1(2)']
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
