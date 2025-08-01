control 'SV-91669' do
  title 'The DBN-6300 must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised.

This requirement does not include emergency administration accounts which are meant for access to the network device in case of failure. These accounts are not required to have maximum password lifetime restrictions.'
  desc 'check', 'To see if the system requires a maximum password lifetime attempt to login with a user who has had their password set longer then password lifetime setting.

If a user is able to log in successfully, this is a finding.'
  desc 'fix', 'Set the password-maxAge variable within the DBN-6300 through the CLI.

This value is set with the following registry entry in the CLI:
reg set /sysconfig/auth/01 {"stores": {"local": {"policies": {"passwordExpire": {"maxAge": 216000,"action": "reject"}}}}}'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76973'
  tag rid: 'SV-91669r1_rule'
  tag stig_id: 'DBNW-DM-000065'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-83669r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
