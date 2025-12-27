control 'SV-89615' do
  title 'The MQ Appliance network device must uniquely identify and authenticate organizational administrators (or processes acting on behalf of organizational administrators).'
  desc 'To assure accountability and prevent unauthenticated access to the MQ Appliance, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system.'
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

If MQ is not set to LDAP authentication, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 

Configure the LDAP connection as required.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74941'
  tag rid: 'SV-89615r1_rule'
  tag stig_id: 'MQMH-ND-000480'
  tag gtitle: 'SRG-APP-000148-NDM-000246'
  tag fix_id: 'F-81557r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
