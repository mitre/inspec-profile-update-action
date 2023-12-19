control 'SV-239712' do
  title 'vSphere UI must not be configured with the "UserDatabaseRealm" enabled.'
  desc 'The vSphere UI performs user authentication at the application level and not through Tomcat. By default, there is no configuration for the "UserDatabaseRealm" Tomcat authentication mechanism. 

To eliminate unnecessary features and ensure that the vSphere UI remains in its shipping state, the lack of a UserDatabaseRealm configuration must be confirmed.'
  desc 'check', 'At the command prompt, execute the following command:

# grep UserDatabaseRealm /usr/lib/vmware-vsphere-ui/server/conf/server.xml

If the command produces any output, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/server.xml. 

Remove any and all <Realm> nodes.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42945r679240_chk'
  tag severity: 'medium'
  tag gid: 'V-239712'
  tag rid: 'SV-239712r879587_rule'
  tag stig_id: 'VCUI-67-000031'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-42904r679241_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
