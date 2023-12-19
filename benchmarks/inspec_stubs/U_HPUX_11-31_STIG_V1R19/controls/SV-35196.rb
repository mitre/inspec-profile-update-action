control 'SV-35196' do
  title 'All Network File System (NFS) shared system files and system directories must be group-owned by root, bin, sys, or other.'
  desc "Failure to give group-ownership of sensitive files or directories to root provides the members of the owning group with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', %q(List the shares.
# cat /etc/dfs/sharetab | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | cut -f 1,1 -d " "

Check the group ownership of each shared directory.
# ls -lLd <exported directory>

If the directory is not group-owned by root, bin, sys, or other, this is a finding.)
  desc 'fix', 'Change the group owner of the share directory.
# chgrp (root|bin|sys|other) <exported directory>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35041r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22496'
  tag rid: 'SV-35196r2_rule'
  tag stig_id: 'GEN005810'
  tag gtitle: 'GEN005810'
  tag fix_id: 'F-30332r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
