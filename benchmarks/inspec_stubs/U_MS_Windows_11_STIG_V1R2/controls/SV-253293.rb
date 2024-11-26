control 'SV-253293' do
  title 'The system must notify the user when a Bluetooth device attempts to connect.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth, or if Bluetooth is turned off per the organizations policy.

Search for "Bluetooth".
View Bluetooth Settings.
Select "More Bluetooth Options"
If "Alert me when a new Bluetooth device wants to connect" is not checked, this is a finding.'
  desc 'fix', 'Configure Bluetooth to notify users if devices attempt to connect.
View Bluetooth Settings.
Ensure "Alert me when a new Bluetooth device wants to connect" is checked.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56746r828961_chk'
  tag severity: 'medium'
  tag gid: 'V-253293'
  tag rid: 'SV-253293r840170_rule'
  tag stig_id: 'WN11-00-000230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56696r828962_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
