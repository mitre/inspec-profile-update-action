control 'SV-95935' do
  title 'The WebSphere Application Server security cookies must be set to HTTPOnly.'
  desc 'Web applications use cookies to track users across requests. These cookies, while typically not sensitive in themselves, connect you to your existing state on the back end system. If an intruder were to capture one of your cookies, they could potentially use the cookie to act as you. Important Web traffic should be encrypted using SSL. This includes important cookies. 

In the case of WebSphere Application Server, the most important cookie is the LTPA cookie, and therefore it should be configured to be sent only over SSL.'
  desc 'check', 'From the administrative console, navigate to Security >> Global Security.

Expand "Web and SIP security".

Click on "Single sign-on (SSO)".

If "Set security cookies to HTTPOnly" is not selected, this is a finding.'
  desc 'fix', 'From the administrative console, navigate to Security >> Global Security.

Expand "Web and SIP security".

Select "Set security cookies to HTTPOnly".

Click "OK".

Click "Save".

Restart the DMGR and all the JVMs.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-80893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81221'
  tag rid: 'SV-95935r1_rule'
  tag stig_id: 'WBSP-AS-000190'
  tag gtitle: 'SRG-APP-000015-AS-000010'
  tag fix_id: 'F-88001r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
