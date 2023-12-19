control 'SV-235961' do
  title 'Oracle WebLogic must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'Application servers provide a myriad of differing processes, features and functionalities. Some of these processes may be deemed to be unnecessary or too insecure to run on a production DoD system. Application servers must provide the capability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance, for example, disabling dynamic JSP reloading on production application servers as a best practice.'
  desc 'check', "1. Access AC
2. From 'Domain Structure', select 'Deployments'
3. Select a deployment of type 'Web Application' from list of deployments
4. Select 'Configuration' tab -> 'General' tab
5. Ensure 'JSP Page Check' field value is set to '-1', which indicates JSP reloading is disabled within this deployment. Repeat steps 3-5 for all 'Web Application' type deployments
6. For every WebLogic resource within the domain, the 'Configuration' tab and associated subtabs provide the ability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance

If the 'JSP Page Check' field is not set to '-1' or other services or functionality deemed to be non-essential to the server mission is not set to '-1', this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Deployments'
3. Select a deployment of type 'Web Application' from list of deployments
4. Select 'Configuration' tab -> 'General' tab
5. Utilize 'Change Center' to create a new change session
6. Set 'JSP Page Check' field value to '-1', which indicates JSP reloading is disabled within this deployment. Click 'Save'. Repeat steps 3-6 for all 'Web Application' type deployments.
7. For every WebLogic resource within the domain, the 'Configuration' tab and associated subtabs provide the ability to disable or deactivate functionality and services that are deemed to be non-essential to the server mission or can adversely impact server performance"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39180r628659_chk'
  tag severity: 'medium'
  tag gid: 'V-235961'
  tag rid: 'SV-235961r628661_rule'
  tag stig_id: 'WBLC-03-000127'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag fix_id: 'F-39143r628660_fix'
  tag 'documentable'
  tag legacy: ['SV-70525', 'V-56271']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
