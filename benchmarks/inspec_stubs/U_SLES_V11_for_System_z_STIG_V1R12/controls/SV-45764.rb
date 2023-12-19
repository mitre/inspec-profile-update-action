control 'SV-45764' do
  title 'The services file must be group-owned by root, bin, sys, or system.'
  desc "Failure to give ownership of system configuration files to root or a system group provides the designated owner and unauthorized users with the potential to change the system configuration possibly weakening the system's security posture."
  desc 'check', 'Check the group ownership of the services file.

Procedure:
# ls -lL /etc/services

If the file is not group-owned by root, bin, sys, or system, this is a finding'
  desc 'fix', 'Change the group-owner of the services file.

Procedure:
# chgrp root /etc/services'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43118r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22427'
  tag rid: 'SV-45764r1_rule'
  tag stig_id: 'GEN003770'
  tag gtitle: 'GEN003770'
  tag fix_id: 'F-39164r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
