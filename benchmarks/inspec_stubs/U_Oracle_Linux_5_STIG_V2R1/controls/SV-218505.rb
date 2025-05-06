control 'SV-218505' do
  title 'The services file must be owned by root or bin.'
  desc "Failure to give ownership of sensitive files or utilities to root or bin provides the designated owner and unauthorized users with the potential to access sensitive information or change the system configuration possibly weakening the system's security posture."
  desc 'check', 'Check the ownership of the services file.

Procedure:
# ls -lL /etc/services

If the services file is not owned by root or bin, this is a finding.'
  desc 'fix', 'Change the ownership of the services file to root or bin.

Procedure:
# chown root /etc/services'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19980r562648_chk'
  tag severity: 'medium'
  tag gid: 'V-218505'
  tag rid: 'SV-218505r603259_rule'
  tag stig_id: 'GEN003760'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19978r562649_fix'
  tag 'documentable'
  tag legacy: ['V-823', 'SV-63977']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
