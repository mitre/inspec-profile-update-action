control 'SV-220708' do
  title 'Local volumes must be formatted using NTFS.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system.  To support this, volumes must be formatted using the NTFS file system.'
  desc 'check', 'Run "Computer Management".
Navigate to Storage >> Disk Management.

If the "File System" column does not indicate "NTFS" for each volume assigned a drive letter, this is a finding.

This does not apply to system partitions such the Recovery and EFI System Partition.'
  desc 'fix', 'Format all local volumes to use NTFS.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22423r554609_chk'
  tag severity: 'high'
  tag gid: 'V-220708'
  tag rid: 'SV-220708r569187_rule'
  tag stig_id: 'WN10-00-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-22412r554610_fix'
  tag 'documentable'
  tag legacy: ['SV-77843', 'V-63353']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
