control 'SV-106389' do
  title 'The LockOutRealm must be configured with a login lockout time of 15 minutes.'
  desc 'LockOutRealm prevents brute force attacks against user passwords. Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources. Access to LockOutRealm must be configured to control login attempts by local accounts.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'Verify the lockOutTime parameter is set to 900 in the LockOutRealm configuration.

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\Isec7 EMM Suite\\Tomcat\\Config
Open the server.xml file with Notepad.
Select Edit >> Find and search for LockOutRealm.
Verify the lockOutTime parameter is set to 900 in the following file:

<Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="3" lockOutTime="900" >

If the lockOutTime parameter is not set to 900 in the LockOutRealm configuration, this is a finding.'
  desc 'fix', 'Add lockOutTime parameter to the LockOutRealm configuration:

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\Isec7 EMM Suite\\Tomcat\\Config
Open the server.xml file with Notepad.
Select Edit>Find and search for LockOutRealm.
Add the following line is in the server.xml file:

<Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="3" lockOutTime="900" >

Restart the ISEC7 EMM Suite Web service in the services.msc'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97283'
  tag rid: 'SV-106389r1_rule'
  tag stig_id: 'ISEC-06-550310'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-102965r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
