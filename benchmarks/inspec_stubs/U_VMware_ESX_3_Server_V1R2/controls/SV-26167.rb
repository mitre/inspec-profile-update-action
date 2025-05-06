control 'SV-26167' do
  title 'The NFS export configuration file must be group-owned by root, bin, sys, or system.'
  desc "Failure to give group ownership of the NFS export configuration file to root or a system group provides the designated group owner and possible unauthorized users with the potential to change system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the NFS export configuration file. 

Procedure:
# ls -lL <NFS export configuration file>

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the NFS export configuration file to root, bin, sys, or system.
Procedure:
# chgrp root <NFS export file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29274r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22492'
  tag rid: 'SV-26167r1_rule'
  tag stig_id: 'GEN005750'
  tag gtitle: 'GEN005750'
  tag fix_id: 'F-26301r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
