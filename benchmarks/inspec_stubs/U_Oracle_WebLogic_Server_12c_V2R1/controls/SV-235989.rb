control 'SV-235989' do
  title 'Oracle WebLogic must protect against or limit the effects of HTTP types of Denial of Service (DoS) attacks.'
  desc "Employing increased capacity and bandwidth combined with service redundancy can reduce the susceptibility to some DoS attacks. When utilizing an application server in a high risk environment (such as a DMZ), the amount of access to the system from various sources usually increases, as does the system's risk of becoming more susceptible to DoS attacks. 

The application server must be able to be configured to withstand or minimize the risk of DoS attacks. This can be partially achieved if the application server provides configuration options that limit the number of allowed concurrent HTTP connections."
  desc 'check', "1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Ensure 'Maximum in-memory Session' field value is set to an integer value at or lower than an acceptable maximum number of HTTP sessions

If a value is not set in the 'Maximum in-memory Session' field for all deployments, this is a finding."
  desc 'fix', "1. Access AC 
2. From 'Domain Structure', select 'Deployments'
3. Sort 'Deployments' table by 'Type' by click the column header
4. Select an 'Enterprise Application' or 'Web Application' to check the session timeout setting
5. Select 'Configuration' tab -> 'Application' tab for deployments of 'Enterprise Application' type
Select 'Configuration' tab -> 'General' tab for deployments of 'Web Application' type
6. Utilize 'Change Center' to create a new change session
7. Set value in 'Maximum in-memory Session' field value to an integer value at or lower than an acceptable maximum number of HTTP sessions. Click 'Save'
8. Repeat steps 4-7 for each 'Enterprise Application' and 'Web Application' deployment"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39208r628743_chk'
  tag severity: 'medium'
  tag gid: 'V-235989'
  tag rid: 'SV-235989r628745_rule'
  tag stig_id: 'WBLC-08-000236'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-39171r628744_fix'
  tag 'documentable'
  tag legacy: ['SV-70591', 'V-56337']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
