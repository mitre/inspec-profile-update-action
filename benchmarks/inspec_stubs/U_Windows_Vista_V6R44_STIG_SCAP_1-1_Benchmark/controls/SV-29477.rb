control 'SV-29477' do
  title 'Local volumes are not formatted using NTFS.'
  desc 'This is a category 1 finding because the ability to set access permissions and audit critical directories and files is only available by using the NTFS file system.  The capability to assign access permissions to file objects is a DOD policy requirement.
The FAT file system only provides the capability to make files read-only and hidden.  The capability to change these attributes is not restricted to any users.  An unauthorized individual could boot the machine from a floppy disk and gain full and unrecorded access to file data.'
  desc 'fix', 'Format all partitions/drives to use NTFS.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-1081'
  tag rid: 'SV-29477r1_rule'
  tag gtitle: 'NTFS Requirement'
  tag fix_id: 'F-53r1_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
