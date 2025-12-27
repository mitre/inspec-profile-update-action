control 'SV-221425' do
  title 'The CustomIdentityPrivateKeyPassPhrase property of the Node Manager configured to support OHS must be configured for secure communication.'
  desc 'Oracle Node Manager is the utility that is used to perform common operational tasks for OHS.

The "CustomIdentityPrivateKeyPassPhrase" is the password that protects the private key when creating certificates.  If a password is not used, the private key is not protected and can be used by any user or attacker that can get access to the private key.'
  desc 'check', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityPrivateKeyPassPhrase" property.

3. If the property does not exist or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/nodemanager/nodemanager.properties with an editor.

2. Search for the "CustomIdentityPrivateKeyPassPhrase" property.

3. Set the "CustomIdentityPrivateKeyPassPhrase" property to the password protecting the Private Key of the Node Manager identity, add the property if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23140r414958_chk'
  tag severity: 'medium'
  tag gid: 'V-221425'
  tag rid: 'SV-221425r879887_rule'
  tag stig_id: 'OH12-1X-000186'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23129r414959_fix'
  tag 'documentable'
  tag legacy: ['SV-79101', 'V-64611']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
