control 'SV-257224' do
  title 'The macOS system must use an approved antivirus program.'
  desc 'An approved antivirus product must be installed and configured to run.

Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify the macOS system has the XProtect service running with the following command:

/bin/launchctl list | /usr/bin/grep -cE "(com.apple.XprotectFramework.PluginService$|com.apple.XProtect.daemon.scan$)"

If the results show "2", the XProtect Service is running.

If the XProtect service is running, verify that it is configured to update automatically by using the following command:

/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist | /usr/bin/grep "ConfigDataInstall"

ConfigDataInstall = 1;

If the XProtect service is being used and "ConfigDataInstall" is not set to "1", this is a finding.

If XProtect is not active on the system, ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved antivirus solution is loaded on the system. The antivirus solution may be bundled with an approved host-based security solution.

If there is no local antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'Configure the macOS system to automatically update XProtect by installing the "Restrictions Policy" configuration profile.

If XProtect is not being used, install an approved antivirus solution on the system.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60909r922876_chk'
  tag severity: 'high'
  tag gid: 'V-257224'
  tag rid: 'SV-257224r922877_rule'
  tag stig_id: 'APPL-13-002070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60850r905304_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
