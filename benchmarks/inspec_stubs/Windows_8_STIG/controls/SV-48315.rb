control 'SV-48315' do
  title 'Remote assistance must display a warning message when allowing helpdesk personnel to control a system.'
  desc 'Requiring warning text to display when allowing helpdesk personnel to control remote assistance sessions ensures personnel of the activity and enforces the need to monitor the activity.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: ShareControlMessage

Type: REG_SZ
Value: You are about to allow other personnel to remotely control your system.  You must monitor the activity until the session is closed.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Customize warning messages" to "Enabled" with "You are about to allow other personnel to remotely control your system.  You must monitor the activity until the session is closed." entered in the "Display warning message before sharing control:" field.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44989r2_chk'
  tag severity: 'low'
  tag gid: 'V-36692'
  tag rid: 'SV-48315r2_rule'
  tag stig_id: 'WN08-CC-000060'
  tag gtitle: 'WN08-CC-000060'
  tag fix_id: 'F-41449r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWM-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
