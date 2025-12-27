control 'SV-35183' do
  title 'The NFS share configuration file must be group-owned by root, bin, sys or other.'
  desc "Failure to give group ownership of the NFS share configuration file to root, bin, sys or other provides the designated group owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', %q(Check the group ownership of the NFS share configuration file.
# echo `ls -lL /etc/dfs/dfstab` | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | cut -f 4,4 -d " "

If the file is not group-owned by root, bin, sys or other, this is a finding.)
  desc 'fix', 'Change the group ownership of the NFS share configuration file.

# chgrp root /etc/dfs/dfstab'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-38012r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22492'
  tag rid: 'SV-35183r1_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'GEN005750'
  tag fix_id: 'F-33251r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
