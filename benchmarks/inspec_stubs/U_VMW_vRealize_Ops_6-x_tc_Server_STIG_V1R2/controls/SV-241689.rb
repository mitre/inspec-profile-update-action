control 'SV-241689' do
  title 'tc Server CaSa must have the allowTrace parameter set to false.'
  desc 'Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage.'
  desc 'check', 'At the command prompt, execute the following command:

grep allowTrace /usr/lib/vmware-casa/casa-webapp/conf/server.xml

If “allowTrace” is set to "true", this is a finding.

Note: If no line is returned this is NOT a finding.'
  desc 'fix', %q(Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/server.xml.

Navigate to and locate the <Connector> nodes that have 'allowTrace="true"'

Remove the 'allowTrace="true"' setting.)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44965r683927_chk'
  tag severity: 'medium'
  tag gid: 'V-241689'
  tag rid: 'SV-241689r879655_rule'
  tag stig_id: 'VROM-TC-000690'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag fix_id: 'F-44924r683928_fix'
  tag 'documentable'
  tag legacy: ['SV-99663', 'V-89013']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
