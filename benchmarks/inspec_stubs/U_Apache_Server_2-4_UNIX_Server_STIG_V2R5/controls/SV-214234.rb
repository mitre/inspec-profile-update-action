control 'SV-214234' do
  title 'The Apache web server must use a logging mechanism that is configured to alert the Information System Security Officer (ISSO) and System Administrator (SA) in the event of a processing failure.'
  desc 'Reviewing log data allows an investigator to recreate the path of an attacker and to capture forensic data for later use. Log data is also essential to SAs in their daily administrative duties on the hosted system or within the hosted applications.

If the logging system begins to fail, events will not be recorded. Organizations must define logging failure events, at which time the application or the logging mechanism the application uses will provide a warning to the ISSO and SA at a minimum.

'
  desc 'check', 'Work with the SIEM administrator to determine if an alert is configured when audit data is no longer received as expected.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to configure an alert when no audit data is received from Apache based on the defined schedule of connections.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15448r276962_chk'
  tag severity: 'medium'
  tag gid: 'V-214234'
  tag rid: 'SV-214234r879570_rule'
  tag stig_id: 'AS24-U1-000160'
  tag gtitle: 'SRG-APP-000108-WSR-000166'
  tag fix_id: 'F-15446r276963_fix'
  tag satisfies: ['SRG-APP-000108-WSR-000166', 'SRG-APP-000359-WSR-000065']
  tag 'documentable'
  tag legacy: ['SV-102715', 'V-92627']
  tag cci: ['CCI-000139', 'CCI-001855']
  tag nist: ['AU-5 a', 'AU-5 (1)']
end
