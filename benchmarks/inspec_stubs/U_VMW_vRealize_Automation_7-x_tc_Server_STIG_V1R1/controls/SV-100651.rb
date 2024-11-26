control 'SV-100651' do
  title 'tc Server HORIZON must not use the tomcat-users XML database for user management.'
  desc 'User management and authentication can be an essential part of any application hosted by the web server. Along with authenticating users, the user management function must perform several other tasks like password complexity, locking users after a configurable number of failed logons, and management of temporary and emergency accounts; and all of this must be done enterprise-wide.

For historical reasons, tc Server contains a tomcat-users.xml file in the configuration directory. This file was originally used by standalone applications that did not authenticate against an LDAP or other enterprise mechanism. vRA does not use this file.'
  desc 'check', 'At the command prompt, execute the following command:

cat /opt/vmware/horizon/workspace/conf/tomcat-users.xml

If "tomcat-users.xml" file contains any user information, this is a finding.'
  desc 'fix', 'Contact the ISSO and/or SA. 

Determine why user data is being stored in "tomcat-users.xml". 

If the user data is not required then it should be removed.

The vRA appliance does not maintain user data in this file by default.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89693r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90001'
  tag rid: 'SV-100651r1_rule'
  tag stig_id: 'VRAU-TC-000320'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-96743r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
