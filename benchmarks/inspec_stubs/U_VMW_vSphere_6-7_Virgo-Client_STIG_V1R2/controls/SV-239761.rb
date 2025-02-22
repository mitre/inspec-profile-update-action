control 'SV-239761' do
  title 'vSphere Client must limit the number of allowed connections.'
  desc 'Limiting the number of established connections to Sphere Client is a basic denial-of-service protection. Servers where the limit is too high or unlimited can potentially run out of system resources and negatively affect system availability.'
  desc 'check', %q(At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@acceptCount' /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

acceptCount="300" acceptCount="300"

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

Configure each <Connector> node with the following:

acceptCount="300"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-42994r679508_chk'
  tag severity: 'medium'
  tag gid: 'V-239761'
  tag rid: 'SV-239761r879650_rule'
  tag stig_id: 'VCFL-67-000020'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-42953r679509_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
