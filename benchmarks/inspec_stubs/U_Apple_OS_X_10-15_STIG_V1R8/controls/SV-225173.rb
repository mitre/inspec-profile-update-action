control 'SV-225173' do
  title 'The macOS system must be configured to disable the Mail iCloud services.'
  desc "It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The Mail application's connections to Apple's iCloud, must be disabled.

"
  desc 'check', 'To check if Mail iCloud is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudMail

If the result is not “allowCloudMail = 0”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26872r467687_chk'
  tag severity: 'low'
  tag gid: 'V-225173'
  tag rid: 'SV-225173r610901_rule'
  tag stig_id: 'AOSX-15-002015'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26860r467688_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['SV-111725', 'V-102763']
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
