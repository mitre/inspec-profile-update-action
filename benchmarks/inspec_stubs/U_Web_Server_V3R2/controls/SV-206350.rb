control 'SV-206350' do
  title 'The web server must limit the number of allowed simultaneous session requests.'
  desc 'Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks. 

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', 'Review the web server documentation and configuration to determine if the number of simultaneous sessions is limited.

If the parameter is not configured or is unlimited, this is a finding.'
  desc 'fix', 'Configure the web server to limit the number of concurrent sessions.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6611r377642_chk'
  tag severity: 'medium'
  tag gid: 'V-206350'
  tag rid: 'SV-206350r879511_rule'
  tag stig_id: 'SRG-APP-000001-WSR-000001'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-6611r377643_fix'
  tag 'documentable'
  tag legacy: ['SV-53018', 'V-40791']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
