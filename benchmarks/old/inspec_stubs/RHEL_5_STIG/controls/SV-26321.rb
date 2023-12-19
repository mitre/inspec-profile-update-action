control 'SV-26321' do
  title 'The system must require passwords contain at least one lowercase alphabetic character.'
  desc 'To enforce the use of complex passwords, minimum numbers of characters of different classes are mandated.  The use of complex passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques.  Complexity requirements increase the password search space by requiring users to construct passwords from a larger character set than they may otherwise use.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so lcredit=-1

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22305'
  tag rid: 'SV-26321r1_rule'
  tag stig_id: 'GEN000610'
  tag gtitle: 'GEN000610'
  tag fix_id: 'F-31231r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
