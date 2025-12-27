control 'SV-214876' do
  title 'The macOS system must disable iCloud Desktop And Documents.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

'
  desc 'check', 'To view the setting for the iCloud Desktop And Documents configuration, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudDesktopAndDocuments

If the output is null or not "allowCloudDesktopAndDocuments = 0" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16076r397200_chk'
  tag severity: 'medium'
  tag gid: 'V-214876'
  tag rid: 'SV-214876r609363_rule'
  tag stig_id: 'AOSX-13-000562'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16074r397201_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-81631', 'SV-96345']
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
