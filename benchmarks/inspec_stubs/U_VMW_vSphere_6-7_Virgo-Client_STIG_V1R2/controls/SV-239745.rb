control 'SV-239745' do
  title 'vSphere Client must limit the maximum size of a POST request.'
  desc 'The "maxPostSize" value is the maximum size in bytes of the POST that will be handled by the container FORM URL parameter parsing. Limit its size to reduce exposure to a denial-of-service attack. 

If "maxPostSize" is not set, the default value of 2097152 (2MB) is used. Security Token Service is configured in its shipping state to not set a value for "maxPostSize".'
  desc 'check', "At the command prompt, execute the following command:

# xmllint --format --xpath '/Server/Service/Connector/@maxPostSize' /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml

Expected result:

XPath set is empty

If the output does not match the expected result, this is a finding."
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-client/server/configuration/tomcat-server.xml.

Navigate to each of the <Connector> nodes.

Remove any configuration for "maxPostSize".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-42978r679460_chk'
  tag severity: 'medium'
  tag gid: 'V-239745'
  tag rid: 'SV-239745r879511_rule'
  tag stig_id: 'VCFL-67-000003'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-42937r679461_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
