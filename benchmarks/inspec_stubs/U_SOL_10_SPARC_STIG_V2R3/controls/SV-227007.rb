control 'SV-227007' do
  title 'The NFS export configuration file must be group-owned by root, bin, or sys.'
  desc "Failure to give group ownership of the NFS export configuration file to root or system groups provides the designated group owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the NFS export configuration file.

Procedure:
# ls -lL /etc/dfs/dfstab

If the file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the NFS export configuration file.

Procedure:
# chgrp root /etc/dfs/dfstab'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29169r485366_chk'
  tag severity: 'medium'
  tag gid: 'V-227007'
  tag rid: 'SV-227007r603265_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29157r485367_fix'
  tag 'documentable'
  tag legacy: ['SV-26813', 'V-22492']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
