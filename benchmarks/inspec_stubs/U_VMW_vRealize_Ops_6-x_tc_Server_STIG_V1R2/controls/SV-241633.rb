control 'SV-241633' do
  title 'tc Server UI must not use the tomcat-users XML database for user management.'
  desc 'User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks like password complexity, locking users after a configurable number of failed logins, and management of temporary and emergency accounts; and all of this must be done enterprise-wide.

For historical reasons, tc Server contains a tomcat-users.xml file in the configuration directory. This file was originally used by standalone applications that did not authenticate against an LDAP or other enterprise mechanism. vROps does not use this file.'
  desc 'check', 'At the command prompt, execute the following command:

cat /usr/lib/vmware-vcops/tomcat-web-app/conf/tomcat-users.xml

If “tomcat-users.xml” file contains any user information, this is a finding.'
  desc 'fix', 'Contact the ISSO and/or SA. Determine why user data is being stored in the “tomcat-users.xml” file. The vROps appliance does not maintain user data in this file by default.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44909r683759_chk'
  tag severity: 'medium'
  tag gid: 'V-241633'
  tag rid: 'SV-241633r879587_rule'
  tag stig_id: 'VROM-TC-000330'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-44868r683760_fix'
  tag 'documentable'
  tag legacy: ['SV-99551', 'V-88901']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
