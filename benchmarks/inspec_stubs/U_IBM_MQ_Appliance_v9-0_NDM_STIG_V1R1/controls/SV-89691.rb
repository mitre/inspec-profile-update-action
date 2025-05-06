control 'SV-89691' do
  title 'Administrative accounts for device management must be configured on the authentication server and not the MQ Appliance network device itself (except for the emergency administration account).'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network MQ Appliance device management. Maintaining local administrator accounts for daily usage on each MQ Appliance network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some MQ Appliance network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion. 

Administrative accounts for network MQ Appliance device management must be configured on the authentication server and not the MQ Appliance network device itself. The only exception is for the emergency administration account (also known as the account of last resort), which is configured locally on each device. Note that more than one emergency administration account may be permitted if approved.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Verify only one Fallback user is specified. 

If administrative accounts other than the Fallback user are on the local MQ appliance, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 

Configure LDAP server connection requirements as required. 

Specify one privileged Fallback user. 

Remove unauthorized Fallback users or admin accounts.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75017'
  tag rid: 'SV-89691r1_rule'
  tag stig_id: 'MQMH-ND-001450'
  tag gtitle: 'SRG-APP-000516-NDM-000336'
  tag fix_id: 'F-81631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000370']
  tag nist: ['CM-6 b', 'CM-6 (1)']
end
