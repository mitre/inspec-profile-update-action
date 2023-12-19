control 'SV-222469' do
  title 'The application must log application shutdown events.'
  desc 'Forensics is a large part of security incident response.  Applications must provide a record of their actions so application events can be investigated post-event.  

Attackers may attempt to shut off the application logging capability to cover their activity while on the system.  Recording the shutdown event and the time it occurred in the application or  system logs helps to provide forensic evidence that aids in investigating the events.'
  desc 'check', 'Review and monitor the application and system logs.

If an application shutdown event is not recorded in the logs, either initiate a shutdown event and review the logs after reestablishing access or request backup copies of the application or system logs that indicate shutdown events are being recorded.

Alternatively, check for a setting within the application that controls application logging events and determine if application shutdown logging is configured.

If the application is not recording application shutdown events in either the application or system log, or if the application is not configured to record shutdown events, this is a finding.'
  desc 'fix', 'Configure the application or application server to record application shutdown events in the event logs.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-36238r602280_chk'
  tag severity: 'medium'
  tag gid: 'V-222469'
  tag rid: 'SV-222469r508029_rule'
  tag stig_id: 'APSC-DV-000940'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-24128r493316_fix'
  tag 'documentable'
  tag legacy: ['SV-84043', 'V-69421']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
