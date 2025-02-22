control 'SV-239425' do
  title 'Performance Charts must not enable support for TRACE requests.'
  desc '"Trace" is a technique for a user to request internal information about Tomcat. This is useful during product development but should not be enabled in production.

Allowing an attacker to conduct a Trace operation against Performance Charts will expose information that would be useful to perform a more targeted attack. Performance Charts provides the "allowTrace" parameter as a way to disable responding to Trace requests.'
  desc 'check', 'At the command prompt, execute the following command:

# grep allowTrace /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml

If "allowTrace" is set to "true", this is a finding. 

If no line is returned, this is NOT a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-perfcharts/tc-instance/conf/server.xml.

Navigate to and locate:
'allowTrace="true"'

Remove the 'allowTrace="true"' setting.)
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Perfcharts Tomcat'
  tag check_id: 'C-42658r674996_chk'
  tag severity: 'medium'
  tag gid: 'V-239425'
  tag rid: 'SV-239425r674998_rule'
  tag stig_id: 'VCPF-67-000024'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-42617r674997_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
