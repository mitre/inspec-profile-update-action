control 'SV-226239' do
  title 'Local volumes must use a format that supports NTFS attributes.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, local volumes must be formatted using a file system that supports NTFS attributes.'
  desc 'check', 'Open "Computer Management".

Select "Disk Management" under "Storage".

For each local volume, if the file system does not indicate "NTFS", this is a finding.

"ReFS" (Resilient File System) is also acceptable and would not be a finding.

“CSV” (Cluster Share Volumes) is also acceptable and would not be a finding.

This does not apply to system partitions such as the Recovery and EFI System Partition.'
  desc 'fix', 'Format local volumes to use NTFS or ReFS.'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27941r476561_chk'
  tag severity: 'high'
  tag gid: 'V-226239'
  tag rid: 'SV-226239r794530_rule'
  tag stig_id: 'WN12-GE-000005'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27929r476562_fix'
  tag 'documentable'
  tag legacy: ['SV-52843', 'V-1081']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
