control 'SV-256940' do
  title 'The Automation Controller web server must manage sessions.'
  desc 'Session management on client and server is required to protect identity and authorization information.

Sessions for the Automation Controller web server, if compromised, could lead to execution of jobs on remote endpoints as if authenticated.

'
  desc 'check', 'Log in to Automation Controller as an administrator and navigate to Settings >> System >> Miscellaneous Authentication.

The following parameters must be set:

OAuth 2 Timeout Settings < 1800 seconds (No more than 30 minutes). 

The maximum number of simultaneous logged session must not be less than 0 (The default is -1) and must not match the organizationally defined maximum.

Disable the built-in authentication system = ON

Enable HTTP Basic Auth = Off

OAuth 2 Timeout settings: 

"ACCESS_TOKEN_EXPIRE_SECONDS": 31536000000,
 "AUTHORIZATION_CODE_EXPIRE_SECONDS": 600,
 "REFRESH_TOKEN_EXPIRE_SECONDS": 2628000

Allow External Users to Create OAuth2 Tokens = Off

Login redirect override URL = Not Configured or Blank

Social Auth Organization Map = Null

Social Auth Team Map = Null

Social Auth User Fields = Null

If any of these settings are incorrect, this is a finding.'
  desc 'fix', 'Log in to Automation Controller as an administrator and navigate to Settings >> System >> Miscellaneous Authentication.

Click "Edit".

Set the following parameters:

OAuth 2 Timeout Settings < 1800 seconds. 

The maximum number of simultaneous logged session must equal 0 or the organizationally defined maximum.

Disable the built-in authentication system = ON

Enable HTTP Basic Auth = Off

Access Token Expiration = 31536000000

Authorization Code Expiration = 600

Refresh Token Expiration = 2628000

Allow External Users to Create OAuth2 Tokens = Off

Login redirect override URL = Not Configured or Blank

Social Auth Organization Map = Null

Social Auth Team Map = Null

Social Auth User Fields = Null

Click "Save".'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60615r903545_chk'
  tag severity: 'medium'
  tag gid: 'V-256940'
  tag rid: 'SV-256940r903545_rule'
  tag stig_id: 'APWS-AT-000020'
  tag gtitle: 'SRG-APP-000001-WSR-000002'
  tag fix_id: 'F-60557r903541_fix'
  tag satisfies: ['SRG-APP-000001-WSR-000002', 'SRG-APP-000001-WSR-000001', 'SRG-APP-000295-WSR-000012', 'SRG-APP-000295-WSR-000134']
  tag 'documentable'
  tag cci: ['CCI-000054', 'CCI-002361']
  tag nist: ['AC-10', 'AC-12']
end
