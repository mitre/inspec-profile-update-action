control 'SV-234521' do
  title 'The UEM server must be configured to only allow enrolled devices that are compliant with UEM policies and assigned to a user in the application access group to download applications.'
  desc 'If the application install policy is not enforced, malicious applications and vulnerable applications can be installed on managed mobile devices, which could compromise DoD data. 

Satisfies:FMT_MOF.1.1(3) 
Reference:PP-MDM-423206'
  desc 'check', 'Verify the UEM server allows only enrolled devices that are compliant with UEM policies and assigned to a user in the application access group to download applications.

If the UEM server does not allow only enrolled devices that are compliant with UEM policies and assigned to a user in the application access group to download applications, this is a finding.'
  desc 'fix', 'Configure the UEM server to allow only enrolled devices that are compliant with UEM policies and assigned to a user in the application access group to download applications.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37706r851589_chk'
  tag severity: 'medium'
  tag gid: 'V-234521'
  tag rid: 'SV-234521r879751_rule'
  tag stig_id: 'SRG-APP-000378-UEM-000249'
  tag gtitle: 'SRG-APP-000378'
  tag fix_id: 'F-37671r615207_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
