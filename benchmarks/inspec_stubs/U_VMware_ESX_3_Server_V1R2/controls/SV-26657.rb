control 'SV-26657' do
  title 'The services file must be group-owned by root, bin, sys, or system.'
  desc "Failure to give ownership of system configuration files to root or a system group provides the designated owner and unauthorized users with the potential to change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of the services file.

Procedure:
# ls -lL /etc/services

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the services file.

Procedure:
# chgrp root /etc/services'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27692r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22427'
  tag rid: 'SV-26657r1_rule'
  tag stig_id: 'GEN003770'
  tag gtitle: 'GEN003770'
  tag fix_id: 'F-23899r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
