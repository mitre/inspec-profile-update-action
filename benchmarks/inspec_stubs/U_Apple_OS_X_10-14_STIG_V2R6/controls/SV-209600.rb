control 'SV-209600' do
  title 'The macOS system must disable Cloud Document Sync.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

Cloud Document Sync must be disabled.'
  desc 'check', 'To view the setting for the iCloud Desktop and Documents configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudDocumentSync

If the output is null or not "allowCloudDocumentSync = 0", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9851r282282_chk'
  tag severity: 'medium'
  tag gid: 'V-209600'
  tag rid: 'SV-209600r610285_rule'
  tag stig_id: 'AOSX-14-002049'
  tag gtitle: 'SRG-OS-000370-GPOS-00155'
  tag fix_id: 'F-9851r282283_fix'
  tag 'documentable'
  tag legacy: ['SV-105077', 'V-95939']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
