control 'SV-79095' do
  title 'The CustomIdentityKeyStoreFileName property of the Node Manager configured to support OHS must be configured for secure communication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

The "CustomIdentityKeyStoreFileName" property specifies the file name of the identity keystore.  This property is required when the "KeyStores" property is set to "CustomIdentityAndCustomTrust".  Without specifying the "CustomIdentityKeyStoreFileName" property, the Node Manager will not operate properly and may cause the system to fail into an unsecure state.'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityKeyStoreFileName" property.

3. If the property does not exist or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityKeyStoreFileName" property.

3. Set the "CustomIdentityKeyStoreFileName" property to a keystore location that contains a valid DoD certificate for the Node Manager identity, add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65347r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64605'
  tag rid: 'SV-79095r1_rule'
  tag stig_id: 'OH12-1X-000183'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70535r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
