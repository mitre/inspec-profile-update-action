control 'SV-214280' do
  title 'The Apache web server must not perform user management for hosted applications.'
  desc 'User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks such as password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts. All of this must be done enterprise-wide. 
 
The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, like LDAP and Active Directory.'
  desc 'check', "Interview the System Administrator (SA) about the role of the Apache web server. 
 
If the web server is hosting an application, have the SA provide supporting documentation on how the application's user management is accomplished outside of the web server. 
 
If the web server is not hosting an application, this is Not Applicable. 
 
If the web server is performing user management for hosted applications, this is a finding. 
 
If the web server is hosting an application and the SA cannot provide supporting documentation on how the application's user management is accomplished outside of the Apache web server, this is a finding."
  desc 'fix', 'Reconfigure any hosted applications on the Apache web server to perform user management outside the web server. 
 
Document how the hosted application user management is accomplished.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Site'
  tag check_id: 'C-15493r277181_chk'
  tag severity: 'medium'
  tag gid: 'V-214280'
  tag rid: 'SV-214280r612241_rule'
  tag stig_id: 'AS24-U2-000240'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-15491r277182_fix'
  tag 'documentable'
  tag legacy: ['SV-102859', 'V-92771']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
