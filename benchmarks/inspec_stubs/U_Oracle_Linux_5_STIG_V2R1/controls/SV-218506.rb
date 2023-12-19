control 'SV-218506' do
  title 'The services file must be group-owned by root or bin.'
  desc "Failure to give ownership of system configuration files to root or a system group provides the designated owner and unauthorized users with the potential to change the system configuration possibly weakening the system's security posture."
  desc 'check', 'Check the group ownership of the services file.

Procedure:
# ls -lL /etc/services

If the file is not group-owned by root or bin, this is a finding.'
  desc 'fix', 'Change the group-owner of the services file.

Procedure:
# chgrp root /etc/services'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19981r562651_chk'
  tag severity: 'medium'
  tag gid: 'V-218506'
  tag rid: 'SV-218506r603259_rule'
  tag stig_id: 'GEN003770'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19979r562652_fix'
  tag 'documentable'
  tag legacy: ['V-22427', 'SV-63979']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
