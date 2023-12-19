control 'SV-214859' do
  title 'The macOS system must be configured to disable Siri and dictation.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The system preference panes for Siri and dictation must be disabled.

'
  desc 'check', "To check if Siri and dictation has been disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -E '(allowAssistant | IronwoodAllowed)’

If the return is null or not:
“IronwoodAllowed = 0
allowAssistant = 0”, this is a finding."
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16059r397149_chk'
  tag severity: 'medium'
  tag gid: 'V-214859'
  tag rid: 'SV-214859r609363_rule'
  tag stig_id: 'AOSX-13-000523'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16057r397150_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['SV-96293', 'V-81579']
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
