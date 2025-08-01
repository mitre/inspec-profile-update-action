control 'SV-224788' do
  title 'Stack tracing must be disabled in Apache Tomcat.'
  desc 'The default error page shows a full stack trace, which is a disclosure of sensitive information. Removal of unneeded or non-secure functions, ports, protocols, and services mitigate the risk of unauthorized connection of devices, unauthorized transfer of information, or other exploitation of these resources.

The organization must perform a periodic scan/review of the application (as required by CCI-000384) and disable functions, ports, protocols, and services deemed to be unneeded or non-secure.'
  desc 'check', 'Verify stack tracing has been disabled in Apache Tomcat. 

Navigate to the ISEC7 EMM Suite installation directory: <Drive>:\\Program Files\\ISEC7 EMM Suite\\web\\WEB-INF
Open web.xml with Notepad.exe
Scroll to the end of the file.
Confirm there are no comment tags <!--" and "--> and the following exists without comment tags:

 <error-page>
    <exception-type>java.lang.Exception</exception-type>
    <location>/exception.jsp</location>
  </error-page>

If stack tracing has not been disabled in Apache Tomcat, this is a finding.'
  desc 'fix', 'Remove the default error page by updating the web application web.xml file.

 Navigate to the ISEC7 EMM Suite installation directory: <Drive>:\\Program Files\\ISEC7 EMM Suite\\web\\WEB-INF
Open web.xml with Notepad.exe
Scroll to the end of the file.
Remove the comment tags <!--" and "-->

<!--   <error-page>
    <exception-type>java.lang.Exception</exception-type>
    <location>/exception.jsp</location>
  </error-page> -->

Save the changes.

This will acknowledge to the user that an exception occurred without showing any trace or source information.'
  impact 0.5
  ref 'DPMS Target ISEC7 Sphere'
  tag check_id: 'C-26479r461620_chk'
  tag severity: 'medium'
  tag gid: 'V-224788'
  tag rid: 'SV-224788r505933_rule'
  tag stig_id: 'ISEC-06-551200'
  tag gtitle: 'SRG-APP-000383'
  tag fix_id: 'F-26467r461621_fix'
  tag 'documentable'
  tag legacy: ['SV-106395', 'V-97291']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
