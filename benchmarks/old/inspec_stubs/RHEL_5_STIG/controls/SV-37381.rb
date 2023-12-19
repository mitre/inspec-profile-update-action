control 'SV-37381' do
  title 'The /etc/passwd file must not contain password hashes.'
  desc 'If password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'fix', 'Migrate /etc/passwd password hashes to /etc/shadow.
# pwconv'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22347'
  tag rid: 'SV-37381r2_rule'
  tag stig_id: 'GEN001470'
  tag gtitle: 'GEN001470'
  tag fix_id: 'F-31312r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000201']
  tag nist: ['IA-5 (6)']
end
