control 'SV-33601' do
  title 'The ability to run programs from a PowerPoint presentation must be disallowed.'
  desc "Action buttons can be used to launch external programs from PowerPoint presentations. If a malicious person adds an action button to a presentation that launches a dangerous program, it could significantly affect the security of a user's computer and data."
  desc 'check', "The policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Run Programs” must be “Enabled (disable - (don't run any programs))”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\powerpoint\\security

Criteria: If the value RunPrograms is REG_DWORD = 0, this is not a finding."
  desc 'fix', "Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Security “Run Programs” to “Enabled (disable - (don't run any programs))”."
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-34065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17788'
  tag rid: 'SV-33601r1_rule'
  tag stig_id: 'DTOO289 - PowerPoint'
  tag gtitle: 'DTOO289 - Running programs in PowerPoint'
  tag fix_id: 'F-29743r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
