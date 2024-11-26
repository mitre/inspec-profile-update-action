control 'SV-225181' do
  title 'The macOS system must be configured to disable the system preference pane for iCloud.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The iCloud System Preference Pane must be disabled.'
  desc 'check', 'To check if the system has the correct setting in the configuration profile to disable access to the iCloud preference pane, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 DisabledPreferencePanes | grep AppleIDPrefPane

If the return is not “com.apple.preferences.AppleIDPrefPane”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26880r467711_chk'
  tag severity: 'high'
  tag gid: 'V-225181'
  tag rid: 'SV-225181r610901_rule'
  tag stig_id: 'AOSX-15-002031'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-26868r467712_fix'
  tag 'documentable'
  tag legacy: ['SV-111743', 'V-102781']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
