control 'SV-214874' do
  title 'The macOS system must disable iCloud bookmark synchronization.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

'
  desc 'check', 'To view the setting for the iCloud Bookmark Synchronization configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudBookmarks

If the output is null or not "allowCloudBookmarks = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16074r397194_chk'
  tag severity: 'medium'
  tag gid: 'V-214874'
  tag rid: 'SV-214874r609363_rule'
  tag stig_id: 'AOSX-13-000560'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16072r397195_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-81627', 'SV-96341']
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
