control 'SV-90753' do
  title 'The OS X system must be configured to disable Location Services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

Location Services must be disabled.'
  desc 'check', 'Location Services must be disabled. To check if a configuration profile is configured to enforce this setting, run the following command:

/usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableLocationServices

If "DisableLocationServices" is not set to "1", this is a finding.

The setting is found in System Preferences >> Security & Privacy >> Privacy >> Location Services.

If the box that says "Enable Location Services" is checked, this is a finding.

To check if the setting was applied on the command line, run the following command:

/usr/bin/sudo /usr/bin/defaults read /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57` LocationServicesEnabled

If the output is "1" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.

The setting "Enable Location Services" can be found in System Preferences >> Security & Privacy >> Privacy >> Location Services. Uncheck the box that says "Enable Location Services".

It can also be set with the following command:

/usr/bin/sudo /usr/bin/defaults write /private/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd.`/usr/sbin/system_profiler SPHardwareDataType | /usr/bin/grep "Hardware UUID" | /usr/bin/cut -c22-57` LocationServicesEnabled -bool false'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76065'
  tag rid: 'SV-90753r1_rule'
  tag stig_id: 'AOSX-12-000535'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
