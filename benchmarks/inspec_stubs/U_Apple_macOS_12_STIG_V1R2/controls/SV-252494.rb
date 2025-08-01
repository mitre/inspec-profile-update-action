control 'SV-252494' do
  title 'The macOS system must be configured to disable sending diagnostic and usage data to Apple.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The ability to submit diagnostic data to Apple must be disabled.'
  desc 'check', 'Sending diagnostic and usage data to Apple must be disabled.

To check if a configuration profile is configured to enforce this setting, run the following command:

/usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowDiagnosticSubmission

If "allowDiagnosticSubmission" is not set to "0", this is a finding.

Alternately, the setting is found in System Preferences >> Security & Privacy >> Privacy >> Analytics & Improvement.

If the box that says, "Send diagnostic & usage data to Apple" is checked, this is a finding.
If the box that says, "Improve Siri & Dictation" is checked, this is a finding.
If the box that says, "Share with App Developers" is checked, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.

The setting "Send diagnostic & usage data to Apple" can also be configured in System Preferences >> Security & Privacy >> Privacy >> Analytics & Improvement.

Uncheck the box that says, "Share Mac Analytics".
Uncheck the box that says, "Improve Siri & Dictation".
Uncheck the box that says, "Share with App Developers".'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55950r816294_chk'
  tag severity: 'medium'
  tag gid: 'V-252494'
  tag rid: 'SV-252494r816477_rule'
  tag stig_id: 'APPL-12-002021'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-55900r816476_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
