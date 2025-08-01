control 'SV-70227' do
  title 'The web server must use a logging mechanism that is configured to alert the ISSO and SA in the event of a processing failure.'
  desc 'Reviewing log data allows an investigator to recreate the path of an attacker and to capture forensic data for later use. Log data is also essential to system administrators in their daily administrative duties on the hosted system or within the hosted applications. 

If the logging system begins to fail, events will not be recorded. Organizations shall define logging failure events, at which time the application or the logging mechanism the application utilizes will provide a warning to the ISSO and SA at a minimum.'
  desc 'check', 'Review the web server documentation and deployment configuration settings to determine if the web server logging system provides an alert to the ISSO and the SA at a minimum when a processing failure occurs.

If alerts are not sent or the web server is not configured to use a dedicated logging tool that meets this requirement, this is a finding.'
  desc 'fix', 'Configure the web server to provide an alert to the ISSO and SA when log processing failures occur.

If the web server cannot generate alerts, utilize an external logging system that meets this criterion.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56543r2_chk'
  tag severity: 'medium'
  tag gid: 'V-55973'
  tag rid: 'SV-70227r2_rule'
  tag stig_id: 'SRG-APP-000108-WSR-000166'
  tag gtitle: 'SRG-APP-000108-WSR-000166'
  tag fix_id: 'F-60851r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
