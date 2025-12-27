control 'SV-218608' do
  title 'The SSH private host key files must have mode 0600 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', 'Check the permissions for SSH private host key files.

# ls -lL /etc/ssh/*key

If any file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the permissions for the SSH private host key files.

# chmod 0600 /etc/ssh/*key'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20083r562837_chk'
  tag severity: 'medium'
  tag gid: 'V-218608'
  tag rid: 'SV-218608r603259_rule'
  tag stig_id: 'GEN005523'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-20081r562838_fix'
  tag 'documentable'
  tag legacy: ['V-22472', 'SV-63863']
  tag cci: ['CCI-000225', 'CCI-000186']
  tag nist: ['AC-6', 'IA-5 (2) (a) (1)']
end
