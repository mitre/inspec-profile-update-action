control 'SV-239661' do
  title 'The Security Token Service must not be configured with unused realms.'
  desc 'The Security Token Service performs user authentication at the application level and not through Tomcat. To eliminate unnecessary features and ensure that the Security Token Service remains in its shipping state, the lack of a "UserDatabaseRealm" configuration must be confirmed.'
  desc 'check', 'Connect to the PSC, whether external or embedded.

At the command prompt, execute the following command:

# grep UserDatabase /usr/lib/vmware-sso/vmware-sts/conf/server.xml

If the command produces any output, this is a finding.'
  desc 'fix', 'Connect to the PSC, whether external or embedded.

Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml. 

Remove the <Realm> nodes returned in the check.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 STS Tomcat'
  tag check_id: 'C-42894r816706_chk'
  tag severity: 'medium'
  tag gid: 'V-239661'
  tag rid: 'SV-239661r879587_rule'
  tag stig_id: 'VCST-67-000010'
  tag gtitle: 'SRG-APP-000141-WSR-000015'
  tag fix_id: 'F-42853r816707_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
