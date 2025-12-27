control 'SV-90749' do
  title 'The OS X system must be configured to disable sending diagnostic and usage data to Apple.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Sending diagnostic and usage data to Apple must be disabled.'
  desc 'check', 'Sending diagnostic and usage data to Apple must be disabled.

To check if a configuration profile is configured to enforce this setting, run the following command:

/usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep AutoSubmit

If "AutoSubmit" is not set to "0", this is a finding.

Alternately, the setting is found in System Preferences >> Security & Privacy >> Privacy >> Diagnostics & Usage.

If the box that says "Send diagnostic & usage data to Apple" is checked, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Security and Privacy Policy" configuration profile.

The setting "Send diagnostic & usage data to Apple" is found in System Preferences >> Security & Privacy >> Privacy >> Diagnostics & Usage.

Uncheck the box that says "Send diagnostic & usage data to Apple."

To apply the setting from the command line, run the following commands:

/usr/bin/defaults read "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit
/usr/bin/sudo /usr/bin/defaults write "/Library/Application Support/CrashReporter/DiagnosticMessagesHistory.plist" AutoSubmit -bool false
/usr/bin/sudo /bin/chmod 644 /Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist
/usr/bin/sudo /usr/bin/chgrp admin /Library/Application\\ Support/CrashReporter/DiagnosticMessagesHistory.plist'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76061'
  tag rid: 'SV-90749r1_rule'
  tag stig_id: 'AOSX-12-000530'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-82699r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
