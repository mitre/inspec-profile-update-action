control 'SV-214350' do
  title 'The Apache web server must use a logging mechanism that is configured to provide a warning to the Information System Security Officer (ISSO) and System Administrator (SA) when allocated record storage volume reaches 75% of maximum log record storage capacity.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process logs as required. Log processing failures include software/hardware errors, failures in the log capturing mechanisms, and log storage capacity being reached or exceeded. 

If log capacity were to be exceeded, then events subsequently occurring would not be recorded. Organizations must define a maximum allowable percentage of storage capacity serving as an alarming threshold (e.g., web server has exceeded 75% of log storage capacity allocated), at which time the Apache web server or the logging mechanism the web server uses will provide a warning to the ISSO and SA at a minimum. 

This requirement can be met by configuring the Apache web server to use a dedicated log tool that meets this requirement.'
  desc 'check', 'Work with the SIEM administrator to determine if an alert is configured when audit data is no longer received as expected.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to configure an alert when no audit data is received from Apache based on the defined schedule of connections.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15562r505095_chk'
  tag severity: 'medium'
  tag gid: 'V-214350'
  tag rid: 'SV-214350r505936_rule'
  tag stig_id: 'AS24-W1-000740'
  tag gtitle: 'SRG-APP-000359-WSR-000065'
  tag fix_id: 'F-15560r505096_fix'
  tag 'documentable'
  tag legacy: ['SV-102543', 'V-92455']
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
