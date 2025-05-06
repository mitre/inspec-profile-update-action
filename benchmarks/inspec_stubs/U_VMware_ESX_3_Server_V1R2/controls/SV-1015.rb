control 'SV-1015' do
  title 'The ext3 filesystem type must be used for the primary Linux file system partitions.'
  desc 'The ext3 type is most suitable for securing a Linux installation.  It also offers the immutable and append only file attributes which are most useful in protecting system logs and other files.  A file with the append only attribute may only be modified by appending data to the end of the file.  The immutable attribute protects a file from being modified, deleted, or renamed.  In addition, links may not be created to the file.'
  desc 'check', 'Perform the following to check for ext3 filesystems:

# more /etc/fstab

If a local filesystem on a Linux platform is not using ext3, this is a finding.

Note: the CD, floppy drives, proc, and, swap entries do not support ext3.'
  desc 'fix', 'Use the ext3 filesystem type for Linux partitions.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8300r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1015'
  tag rid: 'SV-1015r2_rule'
  tag stig_id: 'GEN000000-LNX00240'
  tag gtitle: 'GEN000000-LNX00240'
  tag fix_id: 'F-1169r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end
