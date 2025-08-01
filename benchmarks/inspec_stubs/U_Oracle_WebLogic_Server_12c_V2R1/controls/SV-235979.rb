control 'SV-235979' do
  title 'Oracle WebLogic must terminate the network connection associated with a communications session at the end of the session or after a DoD-defined time period of inactivity.'
  desc 'If communications sessions remain open for extended periods of time even when unused, there is the potential for an adversary to hijack the session and use it to gain access to the device or networks to which it is attached. Terminating sessions after a certain period of inactivity is a method for mitigating the risk of this vulnerability.

The application server must provide a mechanism for timing out or otherwise terminating inactive web sessions.'
  desc 'check', "1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Ensure 'Session Timeout' field value is set to '900' (seconds)

If the 'Session Timeout' field is not set '900', this is a finding."
  desc 'fix', "1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Utilize 'Change Center' to create a new change session
7. Set value in 'Session Timeout' field value to '900' (seconds). Click 'Save'
8. Repeat steps 4-7 for each 'Enterprise Application' and 'Web Application' deployment"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39198r628713_chk'
  tag severity: 'low'
  tag gid: 'V-235979'
  tag rid: 'SV-235979r628715_rule'
  tag stig_id: 'WBLC-08-000210'
  tag gtitle: 'SRG-APP-000295-AS-000263'
  tag fix_id: 'F-39161r628714_fix'
  tag 'documentable'
  tag legacy: ['SV-70561', 'V-56307']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
