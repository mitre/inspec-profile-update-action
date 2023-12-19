control 'SV-87201' do
  title 'The system must notify the user when a Bluetooth device attempts to connect.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system.  If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth.

Verify Bluetooth notifies users if devices attempt to connect.
Search for "Bluetooth".
Select "Devices and Printers".
View Bluetooth Settings.
If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.'
  desc 'fix', 'Configure Bluetooth to notify users if devices attempt to connect.
View Bluetooth Settings.
Ensure "Alert me when a new Bluetooth device wants to connect" is checked.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-72765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36762'
  tag rid: 'SV-87201r1_rule'
  tag stig_id: 'WIN00-000230'
  tag gtitle: 'WN08-MO-000007'
  tag fix_id: 'F-78971r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
