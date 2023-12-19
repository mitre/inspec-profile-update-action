control 'SV-206374' do
  title 'The web server must not perform user management for hosted applications.'
  desc 'User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks like password complexity, locking users after a configurable number of failed logins, and management of temporary and emergency accounts; and all of this must be done enterprise-wide.

The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, like LDAP and Active Directory.'
  desc 'check', 'Review the web server documentation and configuration to determine if the web server is being used as a user management application.

If the web server is being used to perform user management for the hosted applications, this is a finding.'
  desc 'fix', 'Configure the web server to disable user management functionality.'
  impact 0.5
  ref 'DPMS Target Web Server'
  tag check_id: 'C-6635r377714_chk'
  tag severity: 'medium'
  tag gid: 'V-206374'
  tag rid: 'SV-206374r395853_rule'
  tag stig_id: 'SRG-APP-000141-WSR-000015'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-6635r377715_fix'
  tag 'documentable'
  tag legacy: ['SV-70243', 'V-55989']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
