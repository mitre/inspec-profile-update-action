control 'SV-234235' do
  title 'The UEM Agent must provide an alert via the trusted channel to the UEM Server in the event of any of the following audit events:
-successful application of policies to a mobile device
-receiving or generating periodic reachability events
-change in enrollment state
-failure to install an application from the UEM Server
-failure to update an application from the UEM Server.'
  desc 'Alerts providing notification of a change in enrollment state facilitate verification of the correct operation of security functions. When an UEM server receives such an alert from an UEM Agent, it indicates the security policy may no longer be enforced on the mobile device. This enables the UEM administrator to take an appropriate remedial action.

'
  desc 'check', 'Verify the UEM Agent provides an alert via the trusted channel to the UEM Server in the event of any of the following audit events:
-successful application of policies to a mobile device
-receiving or generating periodic reachability events 
-change in enrollment state
-failure to install an application from the UEM Server
-failure to update an application from the UEM Server.

If the UEM Agent does not provide an alert via the trusted channel to the UEM Server in the event of any of the following audit events:
-successful application of policies to a mobile device 
-receiving or generating periodic reachability events 
-change in enrollment state
-failure to install an application from the UEM Server
-failure to update an application from the UEM Server
this is a finding.'
  desc 'fix', 'Configure the UEM Agent to provide an alert via the trusted channel to the UEM Server in the event of any of the following audit events:
-successful application of policies to a mobile device 
-receiving or generating periodic reachability events 
-change in enrollment state
-failure to install an application from the UEM Server
-failure to update an application from the UEM Server.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37420r617416_chk'
  tag severity: 'medium'
  tag gid: 'V-234235'
  tag rid: 'SV-234235r617416_rule'
  tag stig_id: 'SRG-APP-000089-UEM-100002'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-37385r617388_fix'
  tag satisfies: ['FAU_ALT_EXT.2.1\nReference: PP-UEM-402001', 'PP-UEM-402002', 'PP-MDM-402003']
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
