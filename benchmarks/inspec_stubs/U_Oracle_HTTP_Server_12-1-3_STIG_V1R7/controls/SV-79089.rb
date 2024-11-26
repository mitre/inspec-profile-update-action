control 'SV-79089' do
  title 'The ListenAddress property of the Node Manager configured to support OHS must match the CN of the certificate used by Node Manager.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

For connections to be made to the Node Manager, it must listen on an assigned address.  When this parameter is not set, the Node Manager will listen on all available addresses on the server.  This may lead to the Node Manager listening on networks, i.e., public network space, where Node Manager may become susceptible to attack instead of being limited to listening for connections on a controlled and secure management network.  It is also important that the address specified matches the CN of the Node Manager.'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "ListenAddress" property.

3. If the property does not exist or is not set to the CN of the Node Manager certificate, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "ListenAddress" property.

3. Set the "ListenAddress" property to the CN of the Node Manager certificate, add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65341r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64599'
  tag rid: 'SV-79089r1_rule'
  tag stig_id: 'OH12-1X-000180'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70529r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
