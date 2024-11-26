control 'SV-239391' do
  title 'ESX Agent Manager must set "URIEncoding" to UTF-8.'
  desc %q(Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application. 

An attacker can also enter Unicode characters into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks. ESX Agent Manager must be configured to use a consistent character set via the "URIEncoding" attribute on the Connector nodes.)
  desc 'check', %q(At the command prompt, execute the following command:

# xmllint --xpath '/Server/Service/Connector/@URIEncoding' /usr/lib/vmware-eam/web/conf/server.xml

Expected result:

URIEncoding="UTF-8"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-eam/web/conf/server.xml

Configure the <Connector> node with the following value:

URIEncoding="UTF-8"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 EAM Tomcat'
  tag check_id: 'C-42624r674665_chk'
  tag severity: 'medium'
  tag gid: 'V-239391'
  tag rid: 'SV-239391r674667_rule'
  tag stig_id: 'VCEM-67-000020'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-42583r674666_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
