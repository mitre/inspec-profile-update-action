control 'SV-26813' do
  title 'The NFS export configuration file must be group-owned by root, bin, or sys.'
  desc "Failure to give group ownership of the NFS export configuration file to root or system groups provides the designated group owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'fix', 'Change the group ownership of the NFS export configuration file.

Procedure:
# chgrp root /etc/dfs/dfstab'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22492'
  tag rid: 'SV-26813r1_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'GEN005750'
  tag fix_id: 'F-24056r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
