control 'SV-222959' do
  title 'Tomcat default ROOT web application must be removed.'
  desc 'The default ROOT web application includes the version of Tomcat that is being used, links to Tomcat documentation, examples, FAQs, and mailing lists. The default ROOT web application must be removed from a publicly accessible Tomcat instance and a more appropriate default page shown to users. It is acceptable to replace the contents of default ROOT with a new default web application.

WARNING: Removing the ROOT folder without replacing the content with valid web based content will result in an error page being displayed to the browser when the browser lands on the default page.'
  desc 'check', 'From the Tomcat server OS type the following command:

sudo ls -l $CATALINA_BASE/webapps/ROOT

Review the index.jsp file. Also review the RELEASE-NOTES.txt file. Look for content that describes the application as being licensed by the Apache Software Foundation. Check the index.jsp for other verbiage that indicates the application is part of the Tomcat server. Alternatively, use a web browser and access the default web application and determine if the website application in the ROOT folder is provided with the Apache Tomcat server.

If the ROOT web application contains Tomcat default application content, this is a finding.'
  desc 'fix', 'WARNING: Removing the ROOT folder without replacing the content with valid web based content will result in an error page being displayed to the browser when the browser lands on the default page.

From the Tomcat server OS:

Either remove the files contained in $CATALINA_BASE/webapps/ROOT folder or replace the content of the folder with a new application that serves as the new default server application.'
  impact 0.3
  ref 'DPMS Target Apache Tomcat Application Server 9'
  tag check_id: 'C-24631r426321_chk'
  tag severity: 'low'
  tag gid: 'V-222959'
  tag rid: 'SV-222959r615938_rule'
  tag stig_id: 'TCAT-AS-000570'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-24620r426322_fix'
  tag 'documentable'
  tag legacy: ['SV-111443', 'V-102501']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
