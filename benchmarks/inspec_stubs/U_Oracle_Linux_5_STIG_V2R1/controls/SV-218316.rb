control 'SV-218316' do
  title 'All run control scripts must have mode 0755 or less permissive.'
  desc 'If the startup files are writable by other users, they could modify the startup files to insert malicious commands into the startup files.'
  desc 'check', 'Check run control script modes.
# cd /etc
# ls -lL rc*
# cd /etc/init.d
# ls -l
If any run control script has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Ensure all system startup files have mode 0755 or less permissive. Examine the "rc" files, and all files in the rc1.d (rc2.d, and so on) directories, and in the /etc/init.d directory to ensure they are not world-writable. If they are world-writable, use the chmod command to correct the vulnerability and research why they are world-writable.

Procedure: 
# chmod 755 <startup file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19791r568828_chk'
  tag severity: 'medium'
  tag gid: 'V-218316'
  tag rid: 'SV-218316r603259_rule'
  tag stig_id: 'GEN001580'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19789r568829_fix'
  tag 'documentable'
  tag legacy: ['V-906', 'SV-63843']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
