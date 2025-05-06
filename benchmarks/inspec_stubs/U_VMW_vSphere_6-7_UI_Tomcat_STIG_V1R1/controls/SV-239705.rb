control 'SV-239705' do
  title 'vSphere UI must not enable support for TRACE requests.'
  desc '"Trace" is a technique for a user to request internal information about Tomcat. This is useful during product development but should not be enabled in production. Allowing an attacker to conduct a Trace operation against the Security Token Service will expose information that would be useful to perform a more targeted attack. vSphere UI provides the "allowTrace" parameter as a means to disable responding to Trace requests.'
  desc 'check', 'At the command prompt, execute the following command:

# grep allowTrace /usr/lib/vmware-vsphere-ui/server/conf/server.xml

If "allowTrace" is set to "true", this is a finding. 

If no line is returned, this is NOT a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml.

Navigate to and locate:

'allowTrace="true"'

Remove the 'allowTrace="true"' setting.)
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42938r679219_chk'
  tag severity: 'medium'
  tag gid: 'V-239705'
  tag rid: 'SV-239705r679221_rule'
  tag stig_id: 'VCUI-67-000024'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-42897r679220_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
