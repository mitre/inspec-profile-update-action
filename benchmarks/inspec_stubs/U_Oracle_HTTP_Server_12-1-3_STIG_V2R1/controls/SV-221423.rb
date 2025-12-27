control 'SV-221423' do
  title 'The CustomIdentityKeyStorePassPhrase property of the Node Manager configured to support OHS must be configured for secure communication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

The "CustomIdentityKeyStorePassPhrase" property is used to protect the data within the keystore.  Without protection, the data within the keystore could be compromised allowing an attacker to use the certificates to gain trusted access to other systems or processes.'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityKeyStorePassPhrase" property.

3. If the property does not exist or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityKeyStorePassPhrase" property.

3. Set the "CustomIdentityKeyStorePassPhrase" property to the password of the keystore that contains a valid DoD certificate for the Node Manager identity, add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23138r414952_chk'
  tag severity: 'medium'
  tag gid: 'V-221423'
  tag rid: 'SV-221423r414954_rule'
  tag stig_id: 'OH12-1X-000184'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23127r414953_fix'
  tag 'documentable'
  tag legacy: ['SV-79097', 'V-64607']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
