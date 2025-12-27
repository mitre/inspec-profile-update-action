control 'SV-39013' do
  title 'The NFS export configuration file must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group ownership of the NFS export configuration file to root or a system group provides the designated group owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', %q(Check the group ownership of the NFS export configuration file.

Procedure:
# echo `ls -lL /etc/exports` | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | cut -f 4,4 -d " "

If the file is not group-owned by root, bin, sys, or other, this is a finding.)
  desc 'fix', 'Change the group ownership of the NFS export configuration file.

# chgrp root /etc/export'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36680r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22492'
  tag rid: 'SV-39013r1_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'GEN005750'
  tag fix_id: 'F-32053r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
