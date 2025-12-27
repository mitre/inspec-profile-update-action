control 'SV-106401' do
  title 'A manager role must be assigned to the Apache Tomcat Web apps (Manager, Host-Manager).'
  desc 'If a manager role is not assigned to the Apache Tomcat web apps, the system administrator will not be able to manage and configure the web apps and security setting may not be configured correctly, with could leave the Apache Tomcat susceptible to attack by an intruder.'
  desc 'check', 'Verify a manager role has been assigned to the Apache Tomcat Web apps (Manager, Host-Manager).

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\
Confirm a user with the manager role to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\tomcat-users.xml exists.

example: <user username="admin" roles="manager-gui,manager-script" ..../>

If  a manager role has not been assigned to the Apache Tomcat Web apps, this is a finding.'
  desc 'fix', 'To add a manager role to the Apache Tomcat Web apps (Manager, Host-Manager), run the ISEC7 integrated installer or use the following manual procedure:

By default there are no users with the manager role assigned. To make use of the manager webapp you need to add a new role and user into the <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\tomcat-users.xml file.

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\
Add a user with the manager role to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\conf\\tomcat-users.xml

example: <user username="admin" roles="manager-gui,manager-script" ..../>

Save the file.'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97297'
  tag rid: 'SV-106401r1_rule'
  tag stig_id: 'ISEC-06-551400'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-102977r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
