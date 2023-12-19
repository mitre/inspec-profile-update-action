control 'SV-218294' do
  title 'The /etc/passwd file must have mode 0644 or less permissive.'
  desc 'If the passwd file is writable by a group-owner or the world, the risk of passwd file compromise is increased.  The passwd file contains the list of accounts on the system and associated information.'
  desc 'check', 'Check the mode of the /etc/passwd file.

Procedure:
# ls -lL /etc/passwd

If /etc/passwd has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the passwd file to 0644.

Procedure:
# chmod 0644 /etc/passwd'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19769r561671_chk'
  tag severity: 'medium'
  tag gid: 'V-218294'
  tag rid: 'SV-218294r603259_rule'
  tag stig_id: 'GEN001380'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19767r561672_fix'
  tag 'documentable'
  tag legacy: ['V-798', 'SV-64557']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
