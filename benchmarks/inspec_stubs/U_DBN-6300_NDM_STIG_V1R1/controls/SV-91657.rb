control 'SV-91657' do
  title 'The DBN-6300 must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

To meet password policy requirements, passwords need to be changed at specific policy-based intervals. 

If the network device allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'To see if the system prohibits password reuse attempt to change the users password deliberately reusing the last passwords used. The user should fail to update their password for the last five passwords that their account has used.

If the user is able to reuse their password before using five different password, this is a finding.'
  desc 'fix', 'Set a password-reuse variable within the DBN-6300 through the CLI.

This value is set with the following registry entry in the CLI:
reg set /sysconfig/auth/01 {"stores": {"local": {"policies": {"passwordReuse": {"check": true,"numberToKeep": 5 }}}}}'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76587r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76961'
  tag rid: 'SV-91657r1_rule'
  tag stig_id: 'DBNW-DM-000056'
  tag gtitle: 'SRG-APP-000165-NDM-000253'
  tag fix_id: 'F-83657r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
