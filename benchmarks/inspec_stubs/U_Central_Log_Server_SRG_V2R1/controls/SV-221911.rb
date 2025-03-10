control 'SV-221911' do
  title 'The Central Log Server must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event.

In the case of centralized logging, the source would be the application name accompanied by the host or client name. 

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging.

Associating information about the source of the event within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server produces audit records containing information to establish the source of the events.

If the Central Log Server is not configured to produce audit records containing information to establish the source of the events, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to produce audit records containing information to establish the source of the events.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23626r420075_chk'
  tag severity: 'low'
  tag gid: 'V-221911'
  tag rid: 'SV-221911r420077_rule'
  tag stig_id: 'SRG-APP-000098-AU-000710'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-23615r420076_fix'
  tag 'documentable'
  tag legacy: ['SV-109155', 'V-100051']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
