control 'SV-89617' do
  title 'In the event the authentication server is unavailable, the MQ Appliance must provide one local account created for emergency administration use.'
  desc "Authentication for administrative (privileged level) access to the MQ Appliance is required at all times. An account can be created on the device's local database for use in an emergency, such as when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is also referred to as the account of last resort since the emergency administration account is strictly intended to be used only as a last resort and immediate administrative access is absolutely necessary. 

The number of emergency administration accounts is restricted to at least one, but no more than operationally required as determined by the Information System Security Officer (ISSO). The emergency administration account logon credentials must be stored in a sealed envelope and kept in a safe. 

MQ provides the Fallback user account to provide access to the MQ appliance in the event the centralized authentication server is not available.v"
  desc 'check', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Verify the Authentication Method is set to LDAP. 

Verify at least one Fallback user is configured. 

If MQ authentication is not set to LDAP and if the Fallback user is not created, this is a finding.'
  desc 'fix', 'Log on to the MQ Appliance WebGUI as a privileged user. Go to Administration (gear icon) >> Access >> RBM Settings. 

Set Authentication Method to LDAP. 

Configure one Fallback user. 

Configure the LDAP connection as required.'
  impact 0.5
  ref 'DPMS Target IBM MQ Appliance v9.0 NDM'
  tag check_id: 'C-74801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74943'
  tag rid: 'SV-89617r1_rule'
  tag stig_id: 'MQMH-ND-000490'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-81559r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
