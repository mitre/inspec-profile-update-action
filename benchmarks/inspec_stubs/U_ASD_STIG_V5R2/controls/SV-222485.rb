control 'SV-222485' do
  title 'The application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Review system documentation and interview application administrator for details regarding logging configuration.

If the application utilizes a centralized logging system that provides the audit processing failure alarms, this requirement is not applicable.

Identify application alarming capability regarding audit processing failure events.

Verify the application is configured to alarm when the auditing system fails.

Example alarm events include but are not limited to: 

hardware failure events
failures to capture audit record events
audit storage errors

If the application is not configured to alarm on alerts that indicate the audit system has failed or is failing, this is a finding.'
  desc 'fix', 'Configure the application to send an alarm in the event the audit system has failed or is failing.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24155r493363_chk'
  tag severity: 'medium'
  tag gid: 'V-222485'
  tag rid: 'SV-222485r508029_rule'
  tag stig_id: 'APSC-DV-001110'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-24144r493364_fix'
  tag 'documentable'
  tag legacy: ['SV-84075', 'V-69453']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
