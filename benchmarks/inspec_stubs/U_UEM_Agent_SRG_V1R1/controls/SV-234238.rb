control 'SV-234238' do
  title 'The UEM Agent must record within each UEM Agent audit record the following information:

-date and time of the event
-type of event
-subject identity
-(if relevant) the outcome (success or failure) of the event.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. For audit logs to be useful, administrators must have the ability to view them.

'
  desc 'check', 'Verify the UEM Agent records within each UEM Agent audit record the following information:
-Date and time of the event
-type of event
-subject identity
-(if relevant) the outcome (success or failure) of the event.

If the UEM Agent does not record within each UEM Agent audit record the following information:
-Date and time of the event
-type of event
-subject identity
-(if relevant) the outcome (success or failure) of the event
this is a finding.'
  desc 'fix', 'Configure the UEM Agent to record within each UEM Agent audit record the following information:
-Date and time of the event
-type of event
-subject identity
-(if relevant) the outcome (success or failure) of the event.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Agent'
  tag check_id: 'C-37423r617417_chk'
  tag severity: 'medium'
  tag gid: 'V-234238'
  tag rid: 'SV-234238r617417_rule'
  tag stig_id: 'SRG-APP-000097-UEM-100005'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-37388r612021_fix'
  tag satisfies: ['FAU_GEN.1.2(2) Refinement']
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
