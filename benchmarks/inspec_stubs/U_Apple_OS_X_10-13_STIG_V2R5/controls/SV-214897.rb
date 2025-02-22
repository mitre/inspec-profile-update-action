control 'SV-214897' do
  title 'The macOS system must be configured so that Bluetooth devices are not allowed to wake the computer.'
  desc 'A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.

The session lock is implemented at the point where session activity can be determined.

Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.'
  desc 'check', 'To check if the Bluetooth Remote Wake setting is disabled, run the following two commands as the primary user:

/usr/bin/defaults -currentHost read com.apple.Bluetooth RemoteWakeEnabled

/usr/bin/defaults read /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | cut -c22-57`.plist RemoteWakeEnabled

If there is an error or nothing is returned, or the return value is "1" for either command, this is a finding.'
  desc 'fix', 'Manually change this control on the computer by opening System Preferences >> Bluetooth.

Click "Advanced" and ensure the "Allow Bluetooth devices to wake this computer" is not checked. This control is not necessary if Bluetooth has been completely disabled.

The following can be run from the command line to disable "Remote Wake" for the current user:

/usr/bin/defaults write /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57`.plist RemoteWakeEnabled 0'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16097r397263_chk'
  tag severity: 'medium'
  tag gid: 'V-214897'
  tag rid: 'SV-214897r609363_rule'
  tag stig_id: 'AOSX-13-000955'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16095r397264_fix'
  tag 'documentable'
  tag legacy: ['SV-96387', 'V-81673']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
