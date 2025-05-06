control 'SV-214239' do
  title 'The Apache web server must not perform user management for hosted applications.'
  desc 'User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks such as password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts. All of this must be done enterprise-wide.

The web server contains a minimal user management function, but the web server user management function does not offer enterprise-wide user management, and user management is not the primary function of the web server. User management for the hosted applications should be done through a facility that is built for enterprise-wide user management, such as LDAP and Active Directory.'
  desc 'check', 'Review the web server documentation and configuration to determine if the web server is being used as a user management application.
 
Search for "AuthUserFile" in the configuration files in the installed Apache Path.
 
Example:

grep -rin AuthUserFile *
 
If there are uncommented lines pointing to files on disk using the above configuration option, this is a finding.'
  desc 'fix', 'Comment out the "AuthUserFile" lines found in the Apache configuration.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15453r276977_chk'
  tag severity: 'medium'
  tag gid: 'V-214239'
  tag rid: 'SV-214239r879587_rule'
  tag stig_id: 'AS24-U1-000240'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-15451r276978_fix'
  tag 'documentable'
  tag legacy: ['SV-102727', 'V-92639']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
