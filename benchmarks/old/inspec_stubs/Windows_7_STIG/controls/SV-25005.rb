control 'SV-25005' do
  title 'Local volumes must be formatted using NTFS.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, volumes must be formatted using the NTFS file system.'
  desc 'check', 'Open the Computer Management Console.
Expand "Storage" in the left pane.
Select "Disk Management".

If the file system column does not indicate "NTFS" as the file system for each local hard drive, this is a finding.

Some hardware vendors create a small FAT partition to store troubleshooting and recovery data.  No other files must be stored here.  This must be documented with the ISSO.'
  desc 'fix', 'Format all local partitions/drives to use NTFS.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62051r2_chk'
  tag severity: 'high'
  tag gid: 'V-1081'
  tag rid: 'SV-25005r2_rule'
  tag gtitle: 'NTFS Requirement'
  tag fix_id: 'F-66949r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
