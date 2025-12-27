control 'SV-85301' do
  title 'The ability to run programs from a PowerPoint presentation must be disallowed.'
  desc %q(This policy setting controls the prompting and activation behavior for the "Run Programs" option for action buttons in PowerPoint. If you enable this policy setting, you can choose from three options to control how the "Run Programs" option functions:- Disable (don't run any programs). If users click an action button with the "Run Programs" action assigned to it, nothing will happen. This option enforces the default configuration in PowerPoint.- Enable (prompt user before running). If users click an action button with the "Run Programs" action assigned to it, PowerPoint will prompt them to continue before running the program.- Enable all (run without prompting). If users click an action button with the "Run Programs" action assigned to it. PowerPoint will run the program automatically, without prompting. If you disable or do not configure this policy setting, if users click an action with the "Run Programs" action assigned to it, nothing will happen. This behavior is the same as Enabled -- Disable (don't run any programs).)
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security "Run Programs" is set to "Disabled". The option 'Enabled: disable (don't run any programs)' is also an acceptable value.  

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\Software\Policies\Microsoft\Office\16.0\PowerPoint\security

Criteria: If the value RunPrograms does not exist, this is not a finding.  If the value is REG_DWORD = 0, this is not a finding.)
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security "Run Programs" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71157r4_chk'
  tag severity: 'medium'
  tag gid: 'V-70677'
  tag rid: 'SV-85301r1_rule'
  tag stig_id: 'DTOO289'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-76999r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
