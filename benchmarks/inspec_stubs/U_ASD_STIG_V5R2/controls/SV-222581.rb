control 'SV-222581' do
  title 'Applications must not use URL embedded session IDs.'
  desc 'Many web development frameworks such as PHP, .NET, and ASP include their own mechanisms for session management. Whenever possible it is recommended to utilize the provided session management framework.

Using a session ID that is copied to the URL introduces the risks that the session ID information will be written to log files, made available in browser history files, or made publicly available within the URL.

Using cookies to establish session ID information is desired.'
  desc 'check', "Review the application documentation and interview the application administrator.

Identify how the application generates session IDs.

If using a web development framework, ask the application administrator to provide details on the framework's session configuration.

Review the framework configuration setting to determine how the session identifiers are created.

Identify any compensating controls that may be leveraged to minimize risk to user sessions.

If the framework or the application is configured to transmit cookies within the URL or via URL rewriting, or if the session ID is created using a GET method and there are no compensating controls configured to address user session security, this is a finding."
  desc 'fix', 'Configure the application to transmit session ID information via cookies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24251r493651_chk'
  tag severity: 'medium'
  tag gid: 'V-222581'
  tag rid: 'SV-222581r508029_rule'
  tag stig_id: 'APSC-DV-002270'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-24240r493652_fix'
  tag 'documentable'
  tag legacy: ['SV-84835', 'V-70213']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
