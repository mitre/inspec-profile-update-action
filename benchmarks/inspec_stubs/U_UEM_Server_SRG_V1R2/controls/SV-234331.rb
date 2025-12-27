control 'SV-234331' do
  title 'The UEM server must be configured to produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event.

In the case of centralized logging, the source would be the application name accompanied by the host or client name. 

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging.

Associating information about the source of the event within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application. 

Satisfies:FAU_GEN.1.2(1) 
Reference:PP-MDM-412060'
  desc 'check', 'Verify the UEM server produces audit records containing information to establish the source of the events.

If the UEM server does not produce audit records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to produce audit records containing information to establish the source of the events.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37516r614003_chk'
  tag severity: 'medium'
  tag gid: 'V-234331'
  tag rid: 'SV-234331r879566_rule'
  tag stig_id: 'SRG-APP-000098-UEM-000058'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-37481r614004_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
