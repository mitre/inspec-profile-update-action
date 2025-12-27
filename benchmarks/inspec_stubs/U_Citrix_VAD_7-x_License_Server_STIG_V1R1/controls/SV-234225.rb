control 'SV-234225' do
  title 'Citrix License Server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', '1. Click "Administration" and select the "Server Configuration" tab.

2. Click the "Web Server Configuration" bar and "Session Timeout".

3. Verify Session Timeout is set to “10”. 

If Session Timeout is not set to “10”, this is a finding.'
  desc 'fix', '1. Click "Administration" and select the "Server Configuration" tab.

2. Click the Web Server Configuration bar.

3. For Session Timeout, enter the value of “10” (minutes).'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x License Server'
  tag check_id: 'C-37410r611926_chk'
  tag severity: 'medium'
  tag gid: 'V-234225'
  tag rid: 'SV-234225r628795_rule'
  tag stig_id: 'CVAD-LS-000880'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-37375r611927_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
