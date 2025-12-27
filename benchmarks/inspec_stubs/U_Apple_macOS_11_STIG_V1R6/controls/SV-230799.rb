control 'SV-230799' do
  title 'The macOS system must be configured to disable iCloud Address Book services.'
  desc "It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The Address Book(Contacts) application's connections to Apple's iCloud must be disabled.

"
  desc 'check', 'Verify that the operating system is configured to disable iCloud Address Book services using the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudAddressBook

If the result is not “allowCloudAddressBook = 0”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33744r607284_chk'
  tag severity: 'low'
  tag gid: 'V-230799'
  tag rid: 'SV-230799r599842_rule'
  tag stig_id: 'APPL-11-002014'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-33717r607285_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
