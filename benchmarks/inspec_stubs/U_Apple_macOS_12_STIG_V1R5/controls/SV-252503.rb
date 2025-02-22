control 'SV-252503' do
  title 'The macOS system must disable iCloud Keychain synchronization.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

Keychain synchronization must be disabled.

'
  desc 'check', 'To view the setting for the iCloud Keychain Synchronization configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudKeychainSync

If the output is null or not "allowCloudKeychainSync = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55959r816321_chk'
  tag severity: 'medium'
  tag gid: 'V-252503'
  tag rid: 'SV-252503r853290_rule'
  tag stig_id: 'APPL-12-002040'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-55909r816322_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-001774', 'CCI-000381']
  tag nist: ['CM-7 (5) (b)', 'CM-7 a']
end
