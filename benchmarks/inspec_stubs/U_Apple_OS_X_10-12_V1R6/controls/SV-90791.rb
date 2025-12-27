control 'SV-90791' do
  title 'The OS X system must be configured with the usbmuxd daemon disabled.'
  desc 'Connections to unauthorized iOS devices (iPhones, iPods, and iPads) open the system to possible compromise via exfiltration of system data. Disabling the "usbmuxd" daemon blocks connections to iOS devices.'
  desc 'check', 'To check if the "usbmuxd" daemon is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.usbmuxd

If the results do not show the following, this is a finding:

"com.apple.usbmuxd" => true'
  desc 'fix', 'To disable the "usbmuxd" daemon, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.usbmuxd

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76103'
  tag rid: 'SV-90791r1_rule'
  tag stig_id: 'AOSX-12-000862'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
