control 'SV-222578' do
  title 'The application must destroy the session ID value and/or cookie on logoff or browser close.'
  desc "Many web development frameworks such as PHP, .NET, and ASP include their own mechanisms for session management. Whenever possible it is recommended to utilize the provided session management framework.

Session cookies contain application session information that can be used to impersonate the web application user or hijack their application session. Once the user's session has terminated, these session IDs must be destroyed and not reused."
  desc 'check', "Review the application documentation and interview the application administrator.

Identify how the application destroys session IDs.

If using a web development framework, ask the application administrator to provide details on the framework's session configuration.

Review framework configuration setting to determine how the session identifiers are destroyed.

Review the client system and using a browser or other tool capable of viewing client cookies, identify cookies set by the application and verify that application session ID cookies are destroyed once the user has logged off or the browser has closed.

If the session IDs and associated cookies are not destroyed on logoff or browser close, this is a finding."
  desc 'fix', 'Configure the application to destroy session ID cookies once the application session has terminated.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24248r493642_chk'
  tag severity: 'high'
  tag gid: 'V-222578'
  tag rid: 'SV-222578r879637_rule'
  tag stig_id: 'APSC-DV-002240'
  tag gtitle: 'SRG-APP-000220'
  tag fix_id: 'F-24237r493643_fix'
  tag 'documentable'
  tag legacy: ['SV-84829', 'V-70207']
  tag cci: ['CCI-001185']
  tag nist: ['SC-23 (1)']
end
