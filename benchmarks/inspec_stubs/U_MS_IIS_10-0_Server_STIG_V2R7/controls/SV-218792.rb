control 'SV-218792' do
  title 'The IIS 10.0 web server must not perform user management for hosted applications.'
  desc 'User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks enterprise-wide, such as password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts.

The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility built for enterprise-wide user management, such as LDAP and Active Directory.'
  desc 'check', "Interview the System Administrator about the role of the IIS 10.0 web server.

If the IIS 10.0 web server is hosting an application, have the SA provide supporting documentation on how the application's user management is accomplished outside of the IIS 10.0 web server.

If the IIS 10.0 web server is not hosting an application, this is Not Applicable.

If the IIS web server is performing user management for hosted applications, this is a finding.

If the IIS 10.0 web server is hosting an application and the SA cannot provide supporting documentation on how the application's user management is accomplished outside of the IIS 10.0 web server, this is a finding."
  desc 'fix', 'Reconfigure any hosted applications on the IIS 10.0 web server to perform user management outside the IIS 10.0 web server.

Document how the hosted application user management is accomplished.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20264r310851_chk'
  tag severity: 'medium'
  tag gid: 'V-218792'
  tag rid: 'SV-218792r561041_rule'
  tag stig_id: 'IIST-SV-000117'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-20262r310852_fix'
  tag 'documentable'
  tag legacy: ['SV-109223', 'V-100119']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
