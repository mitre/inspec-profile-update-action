control 'SV-90799' do
  title 'The OS X system must be configured so that Bluetooth devices are not allowed to wake the computer.'
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
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76111'
  tag rid: 'SV-90799r1_rule'
  tag stig_id: 'AOSX-12-000955'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82749r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
