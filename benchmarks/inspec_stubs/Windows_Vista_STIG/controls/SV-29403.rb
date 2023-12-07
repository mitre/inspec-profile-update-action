control 'SV-29403' do
  title 'Audit of Backup and Restore Privileges is not turned off.'
  desc 'This policy setting stops the system from generating audit events for every file backed up or restored which could fill the Security log in Windows.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Audit: Audit the use of Backup and Restore privilege” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14229'
  tag rid: 'SV-29403r1_rule'
  tag gtitle: 'Audit Backup and Restore Privileges'
  tag fix_id: 'F-13553r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
