control 'SV-40861' do
  title 'The NFS export configuration file must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group ownership of the NFS export configuration file to root or a system group provides the designated group owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the NFS export configuration file. 

Procedure:
# ls -lL /etc/exports

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the NFS export configuration file to root, bin, sys, or system.
Procedure:
# chgrp root /etc/exports'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39553r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22492'
  tag rid: 'SV-40861r1_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'GEN005750'
  tag fix_id: 'F-34706r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
