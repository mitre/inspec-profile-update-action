control 'SV-48439' do
  title 'The system must notify the user when a Bluetooth device attempts to connect.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system.  If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'Verify Bluetooth notifies users if devices attempt to connect.
Search for "Bluetooth".
Select "Devices and Printers".
View Bluetooth Settings.
If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.

If the system does not have Bluetooth, this is not applicable.'
  desc 'fix', 'Configure Bluetooth to notify users if devices attempt to connect.
View Bluetooth Settings.
Ensure "Alert me when a new Bluetooth device wants to connect" is checked.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45104r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36762'
  tag rid: 'SV-48439r2_rule'
  tag stig_id: 'WN08-MO-000007'
  tag gtitle: 'WN08-MO-000007'
  tag fix_id: 'F-41566r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
