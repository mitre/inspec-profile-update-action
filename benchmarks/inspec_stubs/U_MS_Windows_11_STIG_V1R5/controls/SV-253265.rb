control 'SV-253265' do
  title 'Local volumes must be formatted using NTFS.'
  desc 'The ability to set access permissions and auditing is critical to maintaining the security and proper access controls of a system. To support this, volumes must be formatted using the NTFS file system.'
  desc 'check', 'Run "Computer Management".
Navigate to Storage >> Disk Management.

If the "File System" column does not indicate "NTFS" for each volume assigned a drive letter, this is a finding.

This does not apply to system partitions such the Recovery and EFI System Partition.'
  desc 'fix', 'Format all local volumes to use NTFS.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56718r828877_chk'
  tag severity: 'high'
  tag gid: 'V-253265'
  tag rid: 'SV-253265r828879_rule'
  tag stig_id: 'WN11-00-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-56668r828878_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
