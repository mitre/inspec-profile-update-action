control 'SV-206416' do
  title 'Remote access to the web server must follow access policy or work in conjunction with enterprise tools designed to enforce policy requirements.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements. 

Examples of the web server enforcing a remote access policy are implementing IP filtering rules, using https instead of http for communication, implementing secure tokens, and validating users.'
  desc 'check', "Review the web server product documentation and deployed configuration to determine if the server or an enterprise tool is enforcing the organization's requirements for remote connections.

If the web server is not configured to enforce these requirements and an enterprise tool is not in place, this is a finding."
  desc 'fix', 'Configure the web server to enforce the remote access policy or to work with an enterprise tool designed to enforce the policy.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6677r377840_chk'
  tag severity: 'medium'
  tag gid: 'V-206416'
  tag rid: 'SV-206416r879692_rule'
  tag stig_id: 'SRG-APP-000315-WSR-000003'
  tag gtitle: 'SRG-APP-000315'
  tag fix_id: 'F-6677r377841_fix'
  tag 'documentable'
  tag legacy: ['SV-70207', 'V-55953']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
