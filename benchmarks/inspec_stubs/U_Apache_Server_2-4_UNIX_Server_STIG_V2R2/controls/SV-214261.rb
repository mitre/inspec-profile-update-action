control 'SV-214261' do
  title 'Non-privileged accounts on the hosting system must only access Apache web server security-relevant information and functions through a distinct administrative account.'
  desc 'By separating Apache web server security functions from non-privileged users, roles can be developed that can then be used to administer the Apache web server. Forcing users to change from a non-privileged account to a privileged account when operating on the Apache web server or on security-relevant information forces users to only operate as a Web Server Administrator when necessary. Operating in this manner allows for better logging of changes and better forensic information and limits accidental changes to the Apache web server.'
  desc 'check', 'Determine which tool or control file is used to control the configuration of the web server.

If the control of the web server is done via control files, verify who has update access to them. If tools are being used to configure the web server, determine who has access to execute the tools.

If accounts other than the System Administrator (SA), the Web Manager, or the Web Manager designees have access to the web administration tool or control files, this is a finding.'
  desc 'fix', 'Restrict access to the web administration tool to only the System Administrator, Web Manager, or the Web Manager designees.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15475r277043_chk'
  tag severity: 'medium'
  tag gid: 'V-214261'
  tag rid: 'SV-214261r612240_rule'
  tag stig_id: 'AS24-U1-000690'
  tag gtitle: 'SRG-APP-000340-WSR-000029'
  tag fix_id: 'F-15473r277044_fix'
  tag 'documentable'
  tag legacy: ['SV-102801', 'V-92713']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
