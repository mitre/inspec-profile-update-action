control 'SV-218306' do
  title 'The /etc/passwd file must not contain password hashes.'
  desc 'If password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', "Verify no password hashes are present in /etc/passwd.

# cut -d : -f 2 /etc/passwd | egrep -v '^(x|\\*)$'

If any password hashes are returned, this is a finding."
  desc 'fix', 'Migrate /etc/passwd password hashes to /etc/shadow.

# pwconv'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19781r554255_chk'
  tag severity: 'medium'
  tag gid: 'V-218306'
  tag rid: 'SV-218306r603259_rule'
  tag stig_id: 'GEN001470'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19779r554256_fix'
  tag 'documentable'
  tag legacy: ['V-22347', 'SV-64581']
  tag cci: ['CCI-000201', 'CCI-000366']
  tag nist: ['IA-5 (6)', 'CM-6 b']
end
