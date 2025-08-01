control 'SV-227642' do
  title 'The /etc/passwd file must have mode 0644 or less permissive.'
  desc 'If the password file is writable by a group owner or the world, the risk of password file compromise is increased.  The password file contains the list of accounts on the system and associated information.'
  desc 'check', 'Check the mode of the /etc/passwd file.

Procedure:
# ls -lL /etc/passwd

If /etc/passwd has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the passwd file to 0644.

Procedure:
# chmod 0644 /etc/passwd

Document all changes.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29804r488486_chk'
  tag severity: 'medium'
  tag gid: 'V-227642'
  tag rid: 'SV-227642r854477_rule'
  tag stig_id: 'GEN001380'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29792r488487_fix'
  tag 'documentable'
  tag legacy: ['V-798', 'SV-798']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
