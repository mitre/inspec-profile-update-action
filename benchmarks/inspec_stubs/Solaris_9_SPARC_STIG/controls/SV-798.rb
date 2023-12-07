control 'SV-798' do
  title 'The /etc/passwd file must have mode 0644 or less permissive.'
  desc 'If the password file is writable by a group owner or the world, the risk of password file compromise is increased.  The password file contains the list of accounts on the system and associated information.'
  desc 'fix', 'Change the mode of the passwd file to 0644.

Procedure:
# chmod 0644 /etc/passwd

Document all changes.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-798'
  tag rid: 'SV-798r2_rule'
  tag stig_id: 'GEN001380'
  tag gtitle: 'GEN001380'
  tag fix_id: 'F-952r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
