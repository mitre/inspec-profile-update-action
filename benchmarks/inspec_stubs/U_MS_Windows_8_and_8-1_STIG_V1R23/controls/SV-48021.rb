control 'SV-48021' do
  title 'Local volumes must be formatted using NTFS.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system.  To support this, volumes must be formatted using the NTFS file system.'
  desc 'check', 'Open the Computer Management Console.
Expand the "Storage" object in the left pane.
Select the "Disk Management" object.

If the file system column does not indicate "NTFS" as the file system for each local hard drive, this is a finding.

Some hardware vendors create a small FAT partition to store troubleshooting and recovery data. No other files must be stored here.  This must be documented with the ISSO.'
  desc 'fix', 'Format all local partitions/drives to use NTFS.'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44759r3_chk'
  tag severity: 'high'
  tag gid: 'V-1081'
  tag rid: 'SV-48021r2_rule'
  tag stig_id: 'WN08-GE-000005'
  tag gtitle: 'NTFS Requirement'
  tag fix_id: 'F-41159r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
