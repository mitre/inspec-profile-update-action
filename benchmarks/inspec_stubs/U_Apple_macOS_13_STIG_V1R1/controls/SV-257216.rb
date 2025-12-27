control 'SV-257216' do
  title 'The macOS system must be configured to disable the system preference pane for Siri.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems can provide a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The Siri preference pane must be disabled.

'
  desc 'check', 'Verify the macOS system is configured to disable access to the Siri preference pane with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 "DisabledPreferencePanes"

If the result is not an array listing "DisabledPreferencePanes" containing "com.apple.preference.speech", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable access to the Siri preference pane by installing the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60901r905279_chk'
  tag severity: 'medium'
  tag gid: 'V-257216'
  tag rid: 'SV-257216r905281_rule'
  tag stig_id: 'APPL-13-002053'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60842r905280_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
