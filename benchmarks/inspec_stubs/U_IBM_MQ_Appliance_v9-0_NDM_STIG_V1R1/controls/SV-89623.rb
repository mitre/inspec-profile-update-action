control 'SV-89623' do
  title 'The MQ Appliance network device must enforce a minimum 15-character password length.'
  desc "Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. 

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password. 

For LDAP authentication, the authentication server is responsible for enforcing password policy. When the LDAP server is not available, password policy is enforced by the MQ Appliance's RBM password policy."
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Expand Password Policy. 

Verify the (local) Password Policy for the Fallback user minimum length is set to 15. 

If MQ is not set to LDAP authentication or if the local password policy is not configured to meet the requirement, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 

Configure the LDAP server connection as required. 

Expand Password Policy. 

In Password Policy, set minimum password length to 15.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74949'
  tag rid: 'SV-89623r1_rule'
  tag stig_id: 'MQMH-ND-000560'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-81565r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
