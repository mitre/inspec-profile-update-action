control 'SV-228524' do
  title 'The Enable Updates and Disable Updates options in the UI must be hidden from users.'
  desc 'This policy setting allows the user interface (UI) options to enable or disable Office automatic updates to be hidden from users. These options are found in the Product Information area of all Office applications installed via Click-to-Run. This policy setting has no effect on Office applications installed via Windows Installer. If this policy setting is enabled, the "Enable Updates" and "Disable Updates" options in the UI are hidden from users. If this policy setting is not configured, the "Enable Updates" and "Disable Updates" options are visible, and users can enable or disable Office automatic updates from the UI.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine)->Updates->"Hide option to enable or disable updates" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKLM\\software\\policies\\Microsoft\\office\\15.0\\common\\officeupdate

Criteria: If the value HideEnableDisableUpdates is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Microsoft Office 2013 (Machine)->Updates->"Hide option to enable or disable updates"  is set to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2013'
  tag check_id: 'C-30757r498850_chk'
  tag severity: 'medium'
  tag gid: 'V-228524'
  tag rid: 'SV-228524r508020_rule'
  tag stig_id: 'DTOO402'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30742r498851_fix'
  tag 'documentable'
  tag legacy: ['SV-53191', 'V-40859']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
