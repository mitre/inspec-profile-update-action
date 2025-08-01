control 'SV-53993' do
  title 'Scripts in One-Off Outlook forms must be disallowed.'
  desc 'Malicious code can be included within Outlook forms, and such code could be executed when users open the form.  By default, Outlook does not run scripts in forms in which the script and the layout are contained within the message.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Custom Form Security "Allow scripts in one-off Outlook forms" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value EnableOneOffFormScripts is REG_DWORD = 0, this is not a finding'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Custom Form Security "Allow scripts in one-off Outlook forms" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47964r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17562'
  tag rid: 'SV-53993r1_rule'
  tag stig_id: 'DTOO246'
  tag gtitle: 'DTOO246 - Scripts in One-Off Forms'
  tag fix_id: 'F-46882r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
