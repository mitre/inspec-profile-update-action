control 'SV-257200' do
  title 'The macOS system must be configured to disable sending diagnostic and usage data to Apple.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems can provide a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

Sending diagnostic data to Apple must be disabled.'
  desc 'check', 'Verify the macOS system is configured to disable sending diagnostic and usage data to Apple with the following command:

/usr/bin/sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowDiagnosticSubmission"

allowDiagnosticSubmission = 0;

If there is no result, or if "allowDiagnosticSubmission" is not set to "0", this is a finding.

Alternatively, the settings are found in System Settings >> Privacy & Security >> Privacy >> Analytics & Improvements.

If the box "Share Mac Analytics" is checked, this is a finding.

If the box "Improve Siri & Dictation" is checked, this is a finding.

If the box "Share with app developers" is checked, this is a finding.'
  desc 'fix', 'Configure the macOS system to disable sending diagnostic and usage data to Apple by installing the "Restrictions Policy" configuration profile.

Alternatively, the settings can be configured in System Settings >> Privacy & Security >> Privacy >> Analytics & Improvements by performing the following: 

- Uncheck the box, "Share Mac Analytics".
- Uncheck the box "Improve Siri & Dictation".
- Uncheck the box "Share with app developers".'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60885r905231_chk'
  tag severity: 'medium'
  tag gid: 'V-257200'
  tag rid: 'SV-257200r905233_rule'
  tag stig_id: 'APPL-13-002021'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-60826r905232_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
