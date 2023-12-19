control 'SV-223308' do
  title 'Scripted Windows Security restrictions must be enabled in all Office programs.'
  desc "Malicious websites often try to confuse or trick users into giving a site permission to perform an action allowing the site to take control of the users' computers in some manner. Disabling or not configuring this setting allows unknown websites to:
- Create browser windows appearing to be from the local operating system.
- Draw active windows displaying outside of the viewable areas of the screen capturing keyboard input.
- Overlay parent windows with their own browser windows to hide important system information, choices, or prompts."
  desc 'check', 'Verify the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >> Scripted Window Security Restrictions is set to "Enabled" and the check box is selected for every installed Office program.

Use the Windows Registry Editor to navigate to the following key:

HKLM\\Software\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_WINDOW_RESTRICTIONS

If the value for all installed programs is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration >> Administrative Templates >> Microsoft Office 2016 (Machine) >> Security Settings >> IE Security >>Scripted Window Security Restrictions to "Enabled" and select the check boxes for  all installed Office programs.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24981r442143_chk'
  tag severity: 'medium'
  tag gid: 'V-223308'
  tag rid: 'SV-223308r879573_rule'
  tag stig_id: 'O365-CO-000026'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-24969r442144_fix'
  tag 'documentable'
  tag legacy: ['SV-108795', 'V-99691']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
