control 'SV-235985' do
  title 'Oracle WebLogic must terminate user sessions upon user logout or any other organization- or policy-defined session termination events such as idle time limit exceeded.'
  desc 'If communications sessions remain open for extended periods of time even when unused, there is the potential for an adversary to hijack the session and use it to gain access to the device or networks to which it is attached. Terminating sessions after a logout event or after a certain period of inactivity is a method for mitigating the risk of this vulnerability. When a user management session becomes idle, or when a user logs out of the management interface, the application server must terminate the session.'
  desc 'check', "1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Ensure 'Session Timeout' field value is set to organization- or policy-defined session idle time limit

If the 'Session Timeout' field value is not set to an organization- or policy-defined session idle time limit, this is a finding."
  desc 'fix', "1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Utilize 'Change Center' to create a new change session
7. Set value in 'Session Timeout' field value to organization- or policy-defined session idle time limit. Click 'Save'
8. Repeat steps 4-7 for each 'Enterprise Application' and 'Web Application' deployment"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39204r628731_chk'
  tag severity: 'medium'
  tag gid: 'V-235985'
  tag rid: 'SV-235985r628733_rule'
  tag stig_id: 'WBLC-08-000224'
  tag gtitle: 'SRG-APP-000220-AS-000148'
  tag fix_id: 'F-39167r628732_fix'
  tag 'documentable'
  tag legacy: ['SV-70577', 'V-56323']
  tag cci: ['CCI-001185']
  tag nist: ['SC-23 (1)']
end
