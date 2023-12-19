control 'SV-102655' do
  title 'Non-privileged accounts on the hosting system must only access Apache web server security-relevant information and functions through a distinct administrative account.'
  desc 'By separating web server security functions from non-privileged users, roles can be developed that can then be used to administer the web server. Forcing users to change from a non-privileged account to a privileged account when operating on the web server or on security-relevant information forces users to only operate as a web server administrator when necessary. Operating in this manner allows for better logging of changes and better forensic information and limits accidental changes to the web server.'
  desc 'check', 'Determine which tool or control file is used to control the configuration of the web server.

If the control of the web server is done via control files, verify who has update access to them. If tools are being used to configure the web server, determine who has access to execute the tools.

If accounts other than the System Administrator (SA), the Web Manager, or the Web Manager designees have access to the web administration tool or control files, this is a finding.'
  desc 'fix', 'Restrict access to the web administration tool to only the SA, Web Manager, or the Web Manager designees.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92567'
  tag rid: 'SV-102655r1_rule'
  tag stig_id: 'AS24-W2-000690'
  tag gtitle: 'SRG-APP-000340-WSR-000029'
  tag fix_id: 'F-98809r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
