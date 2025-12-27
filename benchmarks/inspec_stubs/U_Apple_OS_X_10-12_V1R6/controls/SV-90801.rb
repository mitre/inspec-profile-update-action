control 'SV-90801' do
  title 'The OS X system must be configured with Bluetooth Sharing disabled.'
  desc 'Bluetooth sharing allows users to wirelessly transmit files between the OS X and Bluetooth-enabled devices, including personally owned cellphones and tablets. A malicious user might introduce viruses or malware onto the system or extract sensitive files. Disabling Bluetooth Sharing mitigates this risk.'
  desc 'check', 'To check if Bluetooth Sharing is enabled, open System Preferences >> Sharing and verify that "Bluetooth Sharing" is not checked "ON".

If it is "ON", this is a finding.

The following command can be run from the command line:

/usr/bin/defaults read /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | grep "Hardware UUID" | cut -c22-57`.plist PrefKeyServicesEnabled

If there is an error or nothing is returned, or the return value is "1", this is a finding.'
  desc 'fix', 'To disable Bluetooth Sharing, open System Preferences >> Sharing and uncheck the box next to "Bluetooth Sharing". This control is not necessary if Bluetooth has been completely disabled.

The following can be run from the command line to disable "Bluetooth Sharing" for the current user:

/usr/bin/defaults write /Users/`whoami`/Library/Preferences/ByHost/com.apple.Bluetooth.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57`.plist PrefKeyServicesEnabled 0'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76113'
  tag rid: 'SV-90801r1_rule'
  tag stig_id: 'AOSX-12-000965'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
