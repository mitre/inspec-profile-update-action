control 'SV-235773' do
  title 'Relaunch notification must be required.'
  desc 'Users must be required to restart the browser to finish installation of pending updates and prevent users from continually using an old/vulnerable browser version.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Notify a user that a browser restart is recommended or required for pending updates" must be set to "enabled" with the option value set to "Required".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "RelaunchNotification" is not set to "REG_DWORD = 2", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Notify a user that a browser restart is recommended or required for pending updates" web-browsing activity to "Required".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38992r626515_chk'
  tag severity: 'medium'
  tag gid: 'V-235773'
  tag rid: 'SV-235773r626523_rule'
  tag stig_id: 'EDGE-00-000061'
  tag gtitle: 'SRG-APP-000156'
  tag fix_id: 'F-38955r626516_fix'
  tag 'documentable'
  tag cci: ['CCI-000396']
  tag nist: ['CM-8 a 3']
end
