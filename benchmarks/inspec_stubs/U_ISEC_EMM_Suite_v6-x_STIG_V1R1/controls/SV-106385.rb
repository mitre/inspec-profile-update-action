control 'SV-106385' do
  title 'LockOutRealm must not be removed from Apache Tomcat.'
  desc 'LockOutRealm prevents brute force attacks against user passwords. Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', %q(Log in to the ISEC7 EMM Suite server.
Navigate to <Drive>:\Program Files\Isec7 EMM Suite\Tomcat\Config
Open the server.xml file with Notepad.
Select Edit >> Find and search for LockOutRealm.
Confirm the following line is in the server.xml file:

<Realm className="org.apache.catalina.realm.LockOutRealm">

If it is not found or has been commented out, this is a finding.

If the LockOutRealm has been removed and can't be used, this is a finding.)
  desc 'fix', 'Login to the ISEC7 EMM Suite server.
Navigate to <Drive>:\\Program Files\\Isec7 EMM Suite\\Tomcat\\Config
Open the server.xml file with Notepad.
Select Edit >> Find and search for LockOutRealm.
Add the following line is in the server.xml file:

<Realm className="org.apache.catalina.realm.LockOutRealm">

Restart the ISEC7 EMM Suite Web service in the services.msc'
  impact 0.5
  ref 'DPMS Target ISEC7 EMM Suite v6.x'
  tag check_id: 'C-96117r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97279'
  tag rid: 'SV-106385r1_rule'
  tag stig_id: 'ISEC-06-550300'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-102961r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
