control 'SV-89635' do
  title 'Authorization for access to the MQ Appliance network device must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed at specific intervals. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the MQ Appliance network device does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the passwords could be compromised. 

This requirement does not include emergency administration accounts meant for access to the MQ Appliance network device in case of failure. These accounts are not required to have maximum password lifetime restrictions. 

For LDAP authentication, the authentication server is responsible for enforcing password policy.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Expand Password Policy. 

Verify the (local) Password Policy Enable Aging check box is selected. 

If MQ is not set to LDAP authentication or if the local password policy is not configured to meet the requirement, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 

Configure LDAP connection as required. 

Expand Password Policy. 

Check the "Enable Aging" check box.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74819r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74961'
  tag rid: 'SV-89635r1_rule'
  tag stig_id: 'MQMH-ND-000660'
  tag gtitle: 'SRG-APP-000174-NDM-000261'
  tag fix_id: 'F-81577r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
