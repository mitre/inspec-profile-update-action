control 'SV-89603' do
  title 'The MQ Appliance network device must enforce the limit of three consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Review LDAP server settings and verify the LDAP configuration limits three consecutive invalid logon attempts by a user during a 15-minute time period 

If MQ is not set to LDAP authentication or if LDAP is not configured to meet the requirement, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 
Configure LDAP connection as required. 

Note: Enforcing the limit of three consecutive invalid logon attempts during a 15-minute time period is the responsibility of the LDAP server.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74929'
  tag rid: 'SV-89603r1_rule'
  tag stig_id: 'MQMH-ND-000150'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-81545r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
