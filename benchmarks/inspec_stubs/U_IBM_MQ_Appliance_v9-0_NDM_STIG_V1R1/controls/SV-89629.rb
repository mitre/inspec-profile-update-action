control 'SV-89629' do
  title 'The MQ Appliance network device must enforce password complexity by requiring that at least one lower-case character be used.'
  desc "Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

For LDAP authentication, the authentication server is responsible for enforcing password policy. When the LDAP server is not available, password policy is enforced by the MQ Appliance's RBM Password Policy."
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Expand Password Policy. 

Verify the (local) Password Policy Require Mixed Case check box is checked. 

If MQ is not set to LDAP authentication or if the local password policy is not configured to meet the requirement, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 

Configure LDAP server connection as required. 

Expand Password Policy. 

Check the Require Mixed Case check box.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74813r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74955'
  tag rid: 'SV-89629r1_rule'
  tag stig_id: 'MQMH-ND-000590'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-81571r1_fix'
  tag 'documentable'
  tag mitigations: 'MQMH-ND-000590'
  tag mitigation_control: 'Configure LDAP connection as required.'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
