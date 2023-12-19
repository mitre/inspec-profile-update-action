control 'SV-41826' do
  title 'The system must require passwords contain at least one uppercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated. The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques. Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so ucredit=-1

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11948'
  tag rid: 'SV-41826r1_rule'
  tag stig_id: 'GEN000600'
  tag gtitle: 'GEN000600'
  tag fix_id: 'F-35446r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
