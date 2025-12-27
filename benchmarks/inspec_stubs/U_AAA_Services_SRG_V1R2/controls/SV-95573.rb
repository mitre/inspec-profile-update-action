control 'SV-95573' do
  title 'AAA Services configuration audit records must identify the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event.

In the case of centralized logging, the source would be the application name accompanied by the host or client name. 

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging.

Associating information about the source of the event within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Verify AAA Services configuration audit records identify the source of the events.

If AAA Services configuration audit records do not identify the source of the events, this is a finding.'
  desc 'fix', 'Configure AAA Services configuration audit records to identify the source of the events.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80863'
  tag rid: 'SV-95573r1_rule'
  tag stig_id: 'SRG-APP-000098-AAA-000250'
  tag gtitle: 'SRG-APP-000098-AAA-000250'
  tag fix_id: 'F-87717r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
