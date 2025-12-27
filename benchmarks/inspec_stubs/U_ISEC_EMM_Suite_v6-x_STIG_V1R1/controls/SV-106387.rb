control 'SV-106387' do
  title 'The LockOutRealm must be configured with a login failure count of 3.'
  desc 'LockOutRealm prevents brute force attacks against user passwords. Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources. Access to LockOutRealm must be configured to control login attempts by local accounts.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'Verify the failureCount parameter is set to 3 in the LockOutRealm configuration.

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\Isec7 EMM Suite\\Tomcat\\Config
Open the server.xml file with Notepad.
Select Edit >> Find and search for LockOutRealm.
Verify the failureCount parameter is set to 3 in the following file:

<Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="3" lockOutTime="900" >

If the failureCount parameter is not set to 3 in the LockOutRealm configuration, this is a finding.'
  desc 'fix', 'Add failureCount parameter to the LockOutRealm configuration:

Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\Isec7 EMM Suite\\Tomcat\\Config
Open the server.xml file with Notepad.
Select Edit >> Find and search for LockOutRealm.
Add the following line is in the server.xml file:

<Realm className="org.apache.catalina.realm.LockOutRealm" failureCount="3" lockOutTime="900" >

Restart the ISEC7 EMM Suite Web service in the services.msc'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96119r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97281'
  tag rid: 'SV-106387r1_rule'
  tag stig_id: 'ISEC-06-550305'
  tag gtitle: 'SRG-APP-000065'
  tag fix_id: 'F-102963r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
