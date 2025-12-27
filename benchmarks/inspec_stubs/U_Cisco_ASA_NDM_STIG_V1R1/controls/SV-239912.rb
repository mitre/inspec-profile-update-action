control 'SV-239912' do
  title 'The Cisco ASA must be configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable.'
  desc "Authentication for administrative (privileged level) access to the device is required at all times. An account can be created on the device's local database for use when the authentication server is down or connectivity between the device and the authentication server is not operable. This account is referred to as the account of last resort since it is intended to be used as a last resort and when immediate administrative access is absolutely necessary.

The account of last resort logon credentials must be stored in a sealed envelope and kept in a safe. The safe must be periodically audited to verify the envelope remains sealed. The signature of the auditor and the date of the audit should be added to the envelope as a record. Administrators should secure the credentials and disable the root account (if possible) when not needed for system administration functions."
  desc 'check', 'Step 1: Review the Cisco ASA configuration to verify that a local account for last resort has been configured with a privilege level that will enable the administrator to troubleshoot connectivity to the authentication server.

username LAST_RESORT password $sha512$5000$tb2eaIcI/Q5Q==$ScFJI1ChS4gIjXw== pbkdf2 privilege 15

Step 2: Verify the fallback to use local account has been configured as shown in the example below.

user-identity default-domain LOCAL
aaa authentication serial console RADIUS_GROUP LOCAL
aaa authentication ssh console RADIUS_GROUP LOCAL

If the Cisco ASA is not configured with only one local account to be used as the account of last resort in the event the authentication server is unavailable, this is a finding.'
  desc 'fix', 'Step 1: Configure a local account with the necessary privilege level to troubleshoot network outage and restore operations as shown in the following example.

ASA(config)# username LAST_RESORT privilege 15
ASA(config)# username LAST_RESORT password xxxxxxxxxxxxx

Step 2: Define the AAA server.

ASA(config)# aaa-server RADIUS_GROUP protocol radius 
ASA(config-aaa-server-group)# exit
ASA(config)# aaa-server RADIUS_GROUP (NDM_INTERFACE) host 10.1.48.10
ASA(config-aaa-server-host)# key xxxxxxxxx
ASA(config-aaa-server-host)# exit

Step 3: Configure the authentication to use an AAA server with the fallback to use the local account if the authentication server is not reachable as shown in the following example.

ASA(config)# aaa authentication serial console RADIUS_GROUP LOCAL
ASA(config)# aaa authentication ssh console RADIUS_GROUP LOCAL
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43145r666097_chk'
  tag severity: 'medium'
  tag gid: 'V-239912'
  tag rid: 'SV-239912r666099_rule'
  tag stig_id: 'CASA-ND-000450'
  tag gtitle: 'SRG-APP-000148-NDM-000346'
  tag fix_id: 'F-43104r666098_fix'
  tag 'documentable'
  tag cci: ['CCI-001358', 'CCI-002111']
  tag nist: ['AC-2 (7) (a)', 'AC-2 a']
end
