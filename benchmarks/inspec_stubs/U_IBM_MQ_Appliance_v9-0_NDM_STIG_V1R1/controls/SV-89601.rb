control 'SV-89601' do
  title 'The MQ Appliance network device access must automatically disable accounts after a 35-day period of account inactivity.'
  desc 'Since the accounts in the MQ Appliance network device are privileged or system-level accounts, account management is vital to the security of the MQ Appliance network device. Inactive accounts could be reactivated or compromised by unauthorized users, allowing exploitation of vulnerabilities and undetected access to the MQ Appliance network device. 

This control does not include emergency administration accounts, which are meant for access to the MQ Appliance network device components in case of network failure.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Review LDAP server settings and verify accounts are configured to be disabled after 35 days of inactivity. 

If MQ is not set to LDAP authentication or if LDAP is not configured to meet the requirement, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. Configure LDAP server connection as required.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74785r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74927'
  tag rid: 'SV-89601r1_rule'
  tag stig_id: 'MQMH-ND-000080'
  tag gtitle: 'SRG-APP-000025-NDM-000207'
  tag fix_id: 'F-81543r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000017']
  tag nist: ['AC-2 (3) (d)']
end
