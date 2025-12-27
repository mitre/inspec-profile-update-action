control 'SV-100625' do
  title 'tc Server ALL must use a logging mechanism that is configured to alert the ISSO and SA in the event of a processing failure.'
  desc 'Reviewing log data allows an investigator to recreate the path of an attacker and to capture forensic data for later use. Log data is also essential to system administrators in their daily administrative duties on the hosted system or within the hosted applications. 

If the logging system begins to fail, events will not be recorded. Organizations must define logging failure events, at which time the application or the logging mechanism the application utilizes will provide a warning to the ISSO and SA at a minimum.'
  desc 'check', 'Interview the ISSO.
 
Determine if log data and records are configured to alert the ISSO and SA in the event of processing failure.
 
If log data and records are not configured to alert the ISSO and SA in the event of processing failure, this is a finding.'
  desc 'fix', 'Configure the web server to provide an alert to the ISSO and SA when log processing failures occur.

If the web server cannot generate alerts, utilize an external logging system that meets this criterion.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89667r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89975'
  tag rid: 'SV-100625r1_rule'
  tag stig_id: 'VRAU-TC-000250'
  tag gtitle: 'SRG-APP-000108-WSR-000166'
  tag fix_id: 'F-96717r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
