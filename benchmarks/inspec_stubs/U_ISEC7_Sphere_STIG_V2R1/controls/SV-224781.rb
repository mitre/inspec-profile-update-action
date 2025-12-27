control 'SV-224781' do
  title 'All Web applications included with Apache Tomcat that are not required must be removed.'
  desc 'Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'Verify CATALINA_HOME/webapps Tomcat administrative tool has been configured to remove all Web applications that are not required.

Log in to the ISEC7 EMM Suite server.
Browse to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\webapps\\
Confirm all folders in the directory with the exception of Manager and Host-Manager have been removed.

If the CATALINA_HOME/webapps Tomcat administrative tool has not been configured to remove all Web applications that are not required, this is a finding.'
  desc 'fix', 'To configure the CATALINA_HOME/webapps Tomcat administrative tool to remove all Web applications that are not required, run the ISEC7 integrated installer or use the following manual procedure: 

Login to the ISEC7 EMM Suite server.
Browse to <Drive>:\\Program Files\\ISEC7 EMM Suite\\Tomcat\\webapps\\
Remove all folders in the directory with the exception of Manager and Host-Manager.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26472r461599_chk'
  tag severity: 'medium'
  tag gid: 'V-224781'
  tag rid: 'SV-224781r505933_rule'
  tag stig_id: 'ISEC-06-550200'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-26460r461600_fix'
  tag 'documentable'
  tag legacy: ['SV-106383', 'V-97277']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
