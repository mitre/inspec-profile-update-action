control 'SV-37344' do
  title 'The /etc/passwd file must have mode 0644 or less permissive.'
  desc 'If the passwd file is writable by a group-owner or the world, the risk of passwd file compromise is increased.  The passwd file contains the list of accounts on the system and associated information.'
  desc 'fix', 'Change the mode of the passwd file to 0644.

Procedure:
# chmod 0644 /etc/passwd'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-798'
  tag rid: 'SV-37344r1_rule'
  tag stig_id: 'GEN001380'
  tag gtitle: 'GEN001380'
  tag fix_id: 'F-31280r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
