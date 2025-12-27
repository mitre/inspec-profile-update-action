control 'SV-227921' do
  title 'The NFS server must not allow remote root access.'
  desc 'If the NFS server allows root access to local file systems from remote hosts, this access could be used to compromise the system.'
  desc 'check', 'Determine if the NFS server is exporting with the root access option.

Procedure:
# exportfs -v | grep "root="
OR
# more /etc/dfs/sharetab

If an export with the root option is found and is not properly documented with the IA staff, this is a finding.'
  desc 'fix', 'Edit the /etc/dfs/dfstab file and remove the root= option from all exports.  Re-export the file systems.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30083r490177_chk'
  tag severity: 'medium'
  tag gid: 'V-227921'
  tag rid: 'SV-227921r603266_rule'
  tag stig_id: 'GEN005880'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30071r490178_fix'
  tag 'documentable'
  tag legacy: ['V-935', 'SV-40307']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
