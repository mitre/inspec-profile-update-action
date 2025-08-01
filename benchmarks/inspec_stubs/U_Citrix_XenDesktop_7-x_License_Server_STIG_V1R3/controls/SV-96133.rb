control 'SV-96133' do
  title 'XenDesktop License Server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', '1. Click "Administration" and select the "Server Configuration" tab.
2. Click the "Web Server Configuration" bar and "Session Timeout".
3. Verify Session Timeout is set to “10”. 

If Session Timeout is not set to “10”, this is a finding.'
  desc 'fix', '1. Click "Administration" and select the "Server Configuration" tab.
2. Click the Web Server Configuration bar.
3. For Session Timeout, enter the value of “10” (minutes).'
  impact 0.5
  ref 'DPMS Target XenDesktop 7.x License Service'
  tag check_id: 'C-81159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81419'
  tag rid: 'SV-96133r1_rule'
  tag stig_id: 'CXEN-LS-000880'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-88235r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
