control 'SV-89597' do
  title 'Access to the MQ Appliance network device must limit the number of concurrent sessions to an organization-defined number for each administrator account and/or administrator account type.'
  desc 'MQ Appliance device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator is helpful in limiting risks related to DoS attacks. 

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Review LDAP server configuration settings and verify the LDAP configuration limits the number of concurrent sessions. 

If MQ is not set to LDAP authentication or if LDAP is not configured to meet the requirement, this is a finding.'
  desc 'fix', "Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP and configure LDAP connection as required. 

Note: Implementation of concurrent session limitation must be enforced by the LDAP server's control of user logons."
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74923'
  tag rid: 'SV-89597r1_rule'
  tag stig_id: 'MQMH-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-81539r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
