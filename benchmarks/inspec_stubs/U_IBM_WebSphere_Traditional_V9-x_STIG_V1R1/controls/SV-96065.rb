control 'SV-96065' do
  title 'The WebSphere Application Server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'When the application server is using PKI authentication, a local revocation cache must be stored for instances when the revocation cannot be authenticated through the network, but if cached authentication information is out of date, the validity of the authentication information may be questionable.'
  desc 'check', 'Review System Security Plan documentation.

Identify the cache timeout parameters for authentication.

Standard value for admin timeout is 10 minutes; however, the ISSO may allow a case by case exception based on operational requirements.

From the admin console, navigate to Security >> Global Security >> Authentication cache settings.

If "Enable authentication cache" check box is set and "Cache timeout" is larger than the parameters specified in the security plan, this is a finding.'
  desc 'fix', 'From the admin console, navigate to Security >> Global Security >> Authentication.

Click on "Authentication cache" settings.

Enter the settings for "Cache timeout" in accordance with the parameters defined in the Systems Security Plan.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81351'
  tag rid: 'SV-96065r1_rule'
  tag stig_id: 'WBSP-AS-001210'
  tag gtitle: 'SRG-APP-000400-AS-000246'
  tag fix_id: 'F-88137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
