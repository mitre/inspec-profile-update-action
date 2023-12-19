control 'SV-218459' do
  title 'The at.allow file must have mode 0600 or less permissive.'
  desc 'Permissions more permissive than 0600 (read, write and execute for the owner) may allow unauthorized or malicious access to the at.allow and/or at.deny files.'
  desc 'check', 'Check the mode of the at.allow file.
# ls -lL /etc/at.allow
If the at.allow file has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Change the mode of the at.allow file.
# chmod 0600 /etc/at.allow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19934r562534_chk'
  tag severity: 'medium'
  tag gid: 'V-218459'
  tag rid: 'SV-218459r603259_rule'
  tag stig_id: 'GEN003340'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19932r562535_fix'
  tag 'documentable'
  tag legacy: ['V-987', 'SV-64453']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
