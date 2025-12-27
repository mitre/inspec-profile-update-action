control 'SV-89693' do
  title 'Access to the MQ Appliance network device must employ automated mechanisms to centrally apply authentication settings.'
  desc 'The use of authentication servers or other centralized management servers for providing centralized authentication services is required for network MQ Appliance device management. Maintaining local administrator accounts for daily usage on each MQ Appliance network device without centralized management is not scalable or feasible. Without centralized management, it is likely that credentials for some MQ Appliance network devices will be forgotten, leading to delays in administration, which itself leads to delays in remediating production problems and in addressing compromises in a timely fashion.

'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

If MQ is not set to LDAP authentication, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 

Configure LDAP server connection requirements as required.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75019'
  tag rid: 'SV-89693r1_rule'
  tag stig_id: 'MQMH-ND-001460'
  tag gtitle: 'SRG-APP-000516-NDM-000337'
  tag fix_id: 'F-81633r1_fix'
  tag satisfies: ['SRG-APP-000516-NDM-000337', 'SRG-APP-000516-NDM-000338', 'SRG-APP-000325-NDM-000285']
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000371', 'CCI-000372', 'CCI-002353']
  tag nist: ['CM-6 b', 'CM-6 (1)', 'CM-6 (1)', 'AC-24 (1)']
end
