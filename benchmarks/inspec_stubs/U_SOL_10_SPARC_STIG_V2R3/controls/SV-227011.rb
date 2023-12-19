control 'SV-227011' do
  title 'All NFS exported system files and system directories must be group-owned by root, bin, or sys.'
  desc "Failure to give group ownership of sensitive files or directories to root provides the members of the owning group with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', 'List the exports.
# cat /etc/dfs/dfstab
OR
# more /etc/dfs/sharetab

For each export, check the ownership information.
# ls -ldL <export>
If the directory is not group-owned by root, sys, or bin this is a finding.'
  desc 'fix', 'Change the group owner of the export directory.
# chgrp root <export>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29173r485378_chk'
  tag severity: 'medium'
  tag gid: 'V-227011'
  tag rid: 'SV-227011r603265_rule'
  tag stig_id: 'GEN005810'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29161r485379_fix'
  tag 'documentable'
  tag legacy: ['V-22496', 'SV-26821']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
