control 'SV-214407' do
  title 'The IIS 8.5 web server must not perform user management for hosted applications.'
  desc 'User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks like password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts; and all of this must be done enterprise-wide.

The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, like LDAP and Active Directory.'
  desc 'check', "Interview the System Administrator about the role of the IIS 8.5 web server.

If the IIS 8.5 web server is hosting an application, have the SA provide supporting documentation on how the application's user management is accomplished outside of the IIS 8.5 web server.

If the IIS 8.5 web server is not hosting an application, this is Not Applicable.

If the IIS web server is performing user management for hosted applications, this is a finding.

If the IIS 8.5 web server is hosting an application and the SA cannot provide supporting documentation on how the application's user management is accomplished outside of the IIS 8.5 web server, this is a finding."
  desc 'fix', 'Reconfigure any hosted applications on the IIS 8.5 web server to perform user management outside the IIS 8.5 web server.

Document how the hosted application user management is accomplished.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15617r310269_chk'
  tag severity: 'medium'
  tag gid: 'V-214407'
  tag rid: 'SV-214407r879587_rule'
  tag stig_id: 'IISW-SV-000117'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-15615r310270_fix'
  tag 'documentable'
  tag legacy: ['SV-91395', 'V-76699']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
