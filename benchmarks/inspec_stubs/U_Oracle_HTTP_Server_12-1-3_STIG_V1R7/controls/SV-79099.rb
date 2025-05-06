control 'SV-79099' do
  title 'The CustomIdentityAlias property of the Node Manager configured to support OHS must be configured for secure communication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.  

The "CustomIdentityAlias" specifies the alias when loading the private key into the keystore.  This property is required when the "KeyStores" property is set to "CustomIdentityAndCustomTrust".  Without specifying the "CustomIdentityKeyStoreFileName" property, the Node Manager will not operate properly and may cause the system to fail into an unsecure state.'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityAlias" property.

3. If the property does not exist or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityAlias" property.

3. Set the "CustomIdentityAlias" property to the alias of the keystore PrivateKeyEntry containing the Node Manager identity, add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65351r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64609'
  tag rid: 'SV-79099r1_rule'
  tag stig_id: 'OH12-1X-000185'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70539r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
