control 'SV-241690' do
  title 'tc Server API must have the allowTrace parameter set to false.'
  desc 'Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.'
  desc 'check', 'At the command prompt, execute the following command:

grep allowTrace /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml

If “allowTrace” is set to "true", this is a finding.

Note: If no line is returned this is NOT a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/server.xml.

Navigate to and locate the <Connector> nodes that have 'allowTrace="true"'

Remove the 'allowTrace="true"' setting.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44966r683930_chk'
  tag severity: 'medium'
  tag gid: 'V-241690'
  tag rid: 'SV-241690r879655_rule'
  tag stig_id: 'VROM-TC-000695'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-44925r683931_fix'
  tag 'documentable'
  tag legacy: ['SV-99665', 'V-89015']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
