control 'SV-225203' do
  title 'The macOS system must use an approved antivirus program.'
  desc 'An approved antivirus product must be installed and configured to run.

Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify the "MRT" service is running by using the following command:

/bin/launchctl print-disabled system | grep mrt

If the results show "com.apple.mrt" => false", the MRT Service is running.

If the MRT service is running, verify that it is configured to update automatically by using the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep ConfigDataInstall

If, "ConfigDataInstall = 1" is not returned, this is a finding.

If the MRT service is not running, ask the System Administrator (SA) or Information System Security Officer (ISSO) if an approved antivirus solution is loaded on the system. The antivirus solution may be bundled with an approved host-based security solution.

If there is no local antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'Enable the MRT service:

/usr/bin/sudo /bin/launchctl enable system/com.apple.mrt

Installing the "Restrictions Policy" will configure the MRT Service to update automatically.

If the MRT Service is not being used, install an approved antivirus solution onto the system.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26902r808445_chk'
  tag severity: 'high'
  tag gid: 'V-225203'
  tag rid: 'SV-225203r808447_rule'
  tag stig_id: 'AOSX-15-002070'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26890r808446_fix'
  tag 'documentable'
  tag legacy: ['V-102825', 'SV-111787']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
