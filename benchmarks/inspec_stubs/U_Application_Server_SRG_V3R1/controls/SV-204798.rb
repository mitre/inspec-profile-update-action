control 'SV-204798' do
  title 'The application server must require users to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

When applications provide the capability to change security roles or escalate the functional capability of the application, it is critical the user re-authenticate.

In addition to the re-authentication requirements associated with session locks, the application server security model may require re-authentication of individuals in other situations, including (but not limited to) the following circumstances:

(i) When authenticators change; 
(ii) When roles change; 
(iii) When security categories of information systems change; 
(iv) When the execution of privileged functions occurs; 
(v) After a fixed period of time; or 
(vi) Periodically.

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes.'
  desc 'check', 'Review the application server documentation and configuration to determine if the application server requires a user to re-authenticate when organization-defined circumstances or situations are met.

If the application server does not require a user to re-authenticate when organization-defined circumstances or situations are met, this is a finding.'
  desc 'fix', 'Configure the application server to require a user to re-authenticate when organization-defined circumstances or situations are met.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4918r283041_chk'
  tag severity: 'medium'
  tag gid: 'V-204798'
  tag rid: 'SV-204798r508029_rule'
  tag stig_id: 'SRG-APP-000389-AS-000253'
  tag gtitle: 'SRG-APP-000389'
  tag fix_id: 'F-4918r283042_fix'
  tag 'documentable'
  tag legacy: ['SV-71799', 'V-57523']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
