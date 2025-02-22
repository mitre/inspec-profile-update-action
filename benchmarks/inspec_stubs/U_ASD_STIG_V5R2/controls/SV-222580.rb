control 'SV-222580' do
  title 'Applications must validate session identifiers.'
  desc 'Many web development frameworks such as PHP, .NET, and ASP include their own mechanisms for session management. Whenever possible it is recommended to utilize the provided session management framework.'
  desc 'check', "Review the application documentation and interview the application administrator.

Identify how the application validates session IDs.

If using a web development framework, ask the application administrator to provide details on the framework's session configuration as it relates to session validation.

If the application is not configured to validate user session identifiers, this is a finding."
  desc 'fix', 'Configure the application to configure user session identifiers.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24250r493648_chk'
  tag severity: 'medium'
  tag gid: 'V-222580'
  tag rid: 'SV-222580r508029_rule'
  tag stig_id: 'APSC-DV-002260'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-24239r493649_fix'
  tag 'documentable'
  tag legacy: ['SV-84833', 'V-70211']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
