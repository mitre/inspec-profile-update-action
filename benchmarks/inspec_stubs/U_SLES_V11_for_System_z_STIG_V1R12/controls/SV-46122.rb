control 'SV-46122' do
  title 'All Network File System (NFS) exported system files and system directories must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group-ownership of sensitive files or directories to root provides the members of the owning group with the potential to access sensitive information or change system configuration which could weaken the system's security posture."
  desc 'check', 'List the exports.
# cat /etc/exports
For each file system displayed, check the ownership.

# ls -ldL <exported file system path>

If the directory is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the export directory.
# chgrp root <export>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43379r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22496'
  tag rid: 'SV-46122r1_rule'
  tag stig_id: 'GEN005810'
  tag gtitle: 'GEN005810'
  tag fix_id: 'F-39463r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
