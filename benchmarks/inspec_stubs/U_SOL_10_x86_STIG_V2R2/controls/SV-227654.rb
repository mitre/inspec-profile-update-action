control 'SV-227654' do
  title 'The /etc/passwd file must not contain password hashes.'
  desc 'If password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', "Verify no password hashes are present in /etc/passwd.
# cut -d : -f 2 /etc/passwd | grep -v '^x$'
If any password hashes are returned, this is a finding."
  desc 'fix', 'Migrate /etc/passwd password hashes to /etc/shadow.
# pwconv'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29816r488522_chk'
  tag severity: 'medium'
  tag gid: 'V-227654'
  tag rid: 'SV-227654r603266_rule'
  tag stig_id: 'GEN001470'
  tag gtitle: 'SRG-OS-000073'
  tag fix_id: 'F-29804r488523_fix'
  tag 'documentable'
  tag legacy: ['V-22347', 'SV-26467']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
