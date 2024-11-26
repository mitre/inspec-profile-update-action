control 'SV-206419' do
  title 'Non-privileged accounts on the hosting system must only access web server security-relevant information and functions through a distinct administrative account.'
  desc 'By separating web server security functions from non-privileged users, roles can be developed that can then be used to administer the web server. Forcing users to change from a non-privileged account to a privileged account when operating on the web server or on security-relevant information forces users to only operate as a web server administrator when necessary. Operating in this manner allows for better logging of changes and better forensic information and limits accidental changes to the web server.'
  desc 'check', 'Review the web server documentation and configuration to determine if accounts used for administrative duties of the web server are separated from non-privileged accounts.

If non-privileged accounts can access web server security-relevant information, this is a finding.'
  desc 'fix', 'Set up accounts and roles that can be used to perform web server security-relevant tasks and remove or modify non-privileged account access to security-relevant tasks.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6680r377849_chk'
  tag severity: 'medium'
  tag gid: 'V-206419'
  tag rid: 'SV-206419r855041_rule'
  tag stig_id: 'SRG-APP-000340-WSR-000029'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-6680r377850_fix'
  tag 'documentable'
  tag legacy: ['SV-70201', 'V-55947']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
