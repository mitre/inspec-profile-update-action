control 'SV-37260' do
  title 'The system must require passwords contain a minimum of 15 characters.'
  desc 'The use of longer passwords reduces the ability of attackers to successfully obtain valid passwords using guessing or exhaustive search techniques by increasing the password search space.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:
password required pam_cracklib.so minlen=15 
prior to the "password include system-auth-ac" line.  

Edit /etc/login.defs to include the line:

PASS_MIN_LEN	15'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-11947'
  tag rid: 'SV-37260r3_rule'
  tag stig_id: 'GEN000580'
  tag gtitle: 'GEN000580'
  tag fix_id: 'F-31206r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
