control 'SV-48317' do
  title 'Remote assistance must display a warning message when allowing helpdesk personnel to connect to a system.'
  desc 'Requiring warning text to display when allowing helpdesk personnel to connect to a system with remote assistance ensures personnel are aware of the activity and enforces the need to monitor the activity.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: ViewMessage

Type: REG_SZ
Value: You are about to allow other personnel to remotely connect to your system.  Sensitive data should not be displayed during this session.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Customize warning messages" to "Enabled" with "You are about to allow other personnel to remotely connect to your system.  Sensitive data should not be displayed during this session." entered in the "Display warning message before connecting:" field.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44990r1_chk'
  tag severity: 'low'
  tag gid: 'V-36694'
  tag rid: 'SV-48317r2_rule'
  tag stig_id: 'WN08-CC-000061'
  tag gtitle: 'WN08-CC-000061'
  tag fix_id: 'F-41450r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWM-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
