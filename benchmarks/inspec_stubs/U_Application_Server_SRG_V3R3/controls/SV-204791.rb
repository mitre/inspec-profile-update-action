control 'SV-204791' do
  title 'The application server must provide an immediate real-time alert to authorized users of all log failure events requiring real-time alerts.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required.  Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded.  Notification of the failure event will allow administrators to take actions so that logs are not lost.'
  desc 'check', 'Review the configuration settings to determine if the application server log system provides a real-time alert to authorized users when log failure events occur requiring real-time alerts.

If designated alerts are not sent to authorized users, this is a finding.'
  desc 'fix', 'Configure the application server to provide a real-time alert to authorized users when log failure events occur that require real-time alerts.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4911r283020_chk'
  tag severity: 'medium'
  tag gid: 'V-204791'
  tag rid: 'SV-204791r850846_rule'
  tag stig_id: 'SRG-APP-000360-AS-000066'
  tag gtitle: 'SRG-APP-000360'
  tag fix_id: 'F-4911r283021_fix'
  tag 'documentable'
  tag legacy: ['SV-71701', 'V-57429']
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
