control 'SV-206415' do
  title 'The web server must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. 

Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.'
  desc 'check', 'Review the hosted applications, web server documentation and deployed configuration to verify that the web server will close an open session after a configurable time of inactivity.

If the web server does not close sessions after a configurable time of inactivity or the amount of time is configured higher than 5 minutes for high-risk applications, 10 minutes for medium-risk applications, or 20 minutes for low-risk applications, this is a finding.'
  desc 'fix', 'Configure the web server to close inactive sessions after 5 minutes for high-risk applications, 10 minutes for medium-risk applications, or 20 minutes for low-risk applications.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6676r377837_chk'
  tag severity: 'medium'
  tag gid: 'V-206415'
  tag rid: 'SV-206415r879673_rule'
  tag stig_id: 'SRG-APP-000295-WSR-000134'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-6676r377838_fix'
  tag 'documentable'
  tag legacy: ['SV-70203', 'V-55949']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
