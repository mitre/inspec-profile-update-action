control 'SV-221421' do
  title 'The KeyStores property of the Node Manager configured to support OHS must be configured for secure communication.'
  desc 'Oracle Node Manager is a utility that can be used to perform common operational tasks across Managed Servers.  These servers can be distributed across multiple machines and geographical locations.  

The "KeyStores" property is used to configure the keystore configuration that will be used by Node Manager to locate its identity (private key and digital certificate) and trust (trusted CA certificates).  The property must be set to "CustomIdentityAndCustomTrust", which causes Node Manager to use an identity and trust keystore created by the SA.'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "KeyStores" property.

3. If the property does not exist or is not set to "CustomIdentityAndCustomTrust", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "KeyStores" property.

3. Set the "KeyStores" property to "CustomIdentityAndCustomTrust", add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23136r414946_chk'
  tag severity: 'medium'
  tag gid: 'V-221421'
  tag rid: 'SV-221421r879887_rule'
  tag stig_id: 'OH12-1X-000182'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23125r414947_fix'
  tag 'documentable'
  tag legacy: ['SV-79093', 'V-64603']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
