control 'SV-214873' do
  title 'The macOS system must disable iCloud document synchronization.'
  desc 'Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

'
  desc 'check', 'To view the setting for the iCloud Document Synchronization configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudDocumentSync

If the output is null or not "allowCloudDocumentSync = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16073r397191_chk'
  tag severity: 'medium'
  tag gid: 'V-214873'
  tag rid: 'SV-214873r609363_rule'
  tag stig_id: 'AOSX-13-000559'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16071r397192_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-81625', 'SV-96339']
  tag cci: ['CCI-001774', 'CCI-000381']
  tag nist: ['CM-7 (5) (b)', 'CM-7 a']
end
