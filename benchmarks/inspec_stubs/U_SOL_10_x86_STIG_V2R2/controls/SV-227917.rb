control 'SV-227917' do
  title 'All NFS-exported system files and system directories must be owned by root.'
  desc "Failure to give ownership of sensitive files or directories  to root provides the designated owner and possible unauthorized users with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', 'Check for NFS exported file systems.

Procedure:
# exportfs -v
OR
# more /etc/dfs/sharetab

This will display all of the exported file systems. For each file system displayed, check the ownership.

Procedure:
# ls -lLa <exported file system path>

If the files and directories are not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of exported file systems not owned by root.

Procedure:
# chown root <path>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30079r490162_chk'
  tag severity: 'medium'
  tag gid: 'V-227917'
  tag rid: 'SV-227917r603266_rule'
  tag stig_id: 'GEN005800'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30067r490163_fix'
  tag 'documentable'
  tag legacy: ['V-931', 'SV-40303']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
