control 'SV-89631' do
  title 'The MQ Appliance network device must enforce password complexity by requiring that at least one numeric character be used.'
  desc "Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

For LDAP authentication, the authentication server is responsible for enforcing password policy. When the LDAP server is not available, password policy is enforced by the MQ Appliance's RBM Password Policy."
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Expand Password Policy. 

Verify the (local) Password Policy Require Number check box is checked. 

If MQ is not set to LDAP authentication or if the local password policy is not configured to meet the requirement, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set the Authentication Method to LDAP. 

Configure LDAP server connection as required. 

Expand Password Policy. 

Check the Password Policy Require Mixed Case check box.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74957'
  tag rid: 'SV-89631r1_rule'
  tag stig_id: 'MQMH-ND-000600'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag fix_id: 'F-81573r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
