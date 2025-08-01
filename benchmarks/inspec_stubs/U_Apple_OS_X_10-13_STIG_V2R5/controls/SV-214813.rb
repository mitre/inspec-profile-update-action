control 'SV-214813' do
  title 'The macOS system must be configured with Wi-Fi support software disabled.'
  desc 'Use of Wi-Fi to connect to unauthorized networks may facilitate the exfiltration of mission data.

'
  desc 'check', 'If the system requires Wi-Fi to connect to an authorized network, this is not applicable.

To check if the Wi-Fi network device is disabled, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -listallnetworkservices

A disabled device will have an asterisk in front of its name.

If the Wi-Fi device is missing this asterisk, this is a finding.'
  desc 'fix', 'To disable the Wi-Fi network device, run the following command:

/usr/bin/sudo /usr/sbin/networksetup -setnetworkserviceenabled "Wi-Fi" off'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16013r397011_chk'
  tag severity: 'medium'
  tag gid: 'V-214813'
  tag rid: 'SV-214813r609363_rule'
  tag stig_id: 'AOSX-13-000070'
  tag gtitle: 'SRG-OS-000300-GPOS-00118'
  tag fix_id: 'F-16011r397012_fix'
  tag satisfies: ['SRG-OS-000300-GPOS-00118', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['V-81485', 'SV-96199']
  tag cci: ['CCI-001443', 'CCI-001444', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8']
end
