control 'SV-230807' do
  title 'The macOS system must be configured to disable the application Calendar.'
  desc "It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The application Calendar establishes connections to Apple's iCloud despite using security controls to disable iCloud access."
  desc 'check', 'To check if there is a configuration policy defined for "Application Restrictions", run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 5 familyControlsEnabled | grep "Calendar"

If the return does not contain "/System/Applications/Calendar.app/Contents/MacOS/Calendar", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33752r607308_chk'
  tag severity: 'medium'
  tag gid: 'V-230807'
  tag rid: 'SV-230807r599842_rule'
  tag stig_id: 'APPL-11-002023'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-33725r607309_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
