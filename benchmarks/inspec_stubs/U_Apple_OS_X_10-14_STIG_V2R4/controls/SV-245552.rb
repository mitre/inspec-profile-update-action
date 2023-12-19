control 'SV-245552' do
  title 'The macOS system must be configured to disable the system preference pane for Siri.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The Siri Preference Pane must be disabled.

'
  desc 'check', %q(To check if the system is configured to disable access to the Siri preference pane and prevent it from being displayed, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 -E 'DisabledPreferencePanes|HiddenPreferencePanes'

If the return is not two arrays (HiddenPreferencePanes and DisabledPreferencePanes) each containing: "com.apple.preference.speech", this is a finding.)
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-48831r755095_chk'
  tag severity: 'medium'
  tag gid: 'V-245552'
  tag rid: 'SV-245552r755097_rule'
  tag stig_id: 'AOSX-14-002053'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-48786r755096_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049']
  tag 'documentable'
  tag cci: ['CCI-001774', 'CCI-000381']
  tag nist: ['CM-7 (5) (b)', 'CM-7 a']
end
