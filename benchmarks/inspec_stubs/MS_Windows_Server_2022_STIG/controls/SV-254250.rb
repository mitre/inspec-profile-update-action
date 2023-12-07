control 'SV-254250' do
  title 'Windows Server 2022 local volumes must use a format that supports NTFS attributes.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, volumes must be formatted using a file system that supports NTFS attributes.'
  desc 'check', 'Open "Computer Management".

Select "Disk Management" under "Storage".

For each local volume, if the file system does not indicate "NTFS", this is a finding.

"ReFS" (resilient file system) is also acceptable and would not be a finding.

This does not apply to system partitions such the Recovery and EFI System Partition.'
  desc 'fix', 'Format volumes to use NTFS or ReFS.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57735r848564_chk'
  tag severity: 'high'
  tag gid: 'V-254250'
  tag rid: 'SV-254250r848566_rule'
  tag stig_id: 'WN22-00-000130'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-57686r848565_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
