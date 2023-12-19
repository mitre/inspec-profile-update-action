control 'SV-99661' do
  title 'tc Server UI must have the allowTrace parameter set to false.'
  desc 'Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.'
  desc 'check', 'At the command prompt, execute the following command:

grep allowTrace /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml

If “allowTrace” is set to "true", this is a finding.

Note: If no line is returned this is NOT a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to and locate the <Connector> nodes that have 'allowTrace="true"'

Remove the 'allowTrace="true"' setting.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89011'
  tag rid: 'SV-99661r1_rule'
  tag stig_id: 'VROM-TC-000685'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-95753r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
