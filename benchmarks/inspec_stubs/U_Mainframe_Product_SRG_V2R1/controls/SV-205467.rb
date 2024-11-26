control 'SV-205467' do
  title 'The Mainframe Product must produce audit records containing information to establish the source of the events.'
  desc 'Without establishing the source of the event, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In addition to logging where events occur within the application, the application must also produce audit records that identify the application itself as the source of the event.

In the case of centralized logging, the source would be the application name accompanied by the host or client name. 

In order to compile an accurate risk assessment, and provide forensic analysis, it is essential for security personnel to know the source of the event, particularly in the case of centralized logging.

Associating information about the source of the event within the application provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured application.'
  desc 'check', 'Examine installation and configuration settings.

Verify data written to external security manager audit files and/or SMF records contain information that details the source of events. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit records written to external security manager audit files and/or SMF records to contain information to establish the source of the events.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5733r299634_chk'
  tag severity: 'medium'
  tag gid: 'V-205467'
  tag rid: 'SV-205467r395730_rule'
  tag stig_id: 'SRG-APP-000098-MFP-000143'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-5733r299635_fix'
  tag 'documentable'
  tag legacy: ['SV-82737', 'V-68247']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
