control 'SV-68751' do
  title 'The ALG providing user authentication intermediary services must require users to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  desc 'Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

In addition to the re-authentication requirements associated with session locks, organizations may require re-authentication of individuals and/or devices in other situations, including (but not limited to) the following circumstances: 

1) When authenticators change
2) When roles change
3) When security categories of information systems change
4) When the execution of privileged functions occurs
5) After a fixed period of time
6) Periodically

Within the DoD, the minimum circumstances requiring re-authentication are privilege escalation and role changes.

This requirement only applies to components where this is specific to the function of the device or has the concept of user authentication (e.g., VPN or ALG capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG is configured to require users to re-authenticate when organization-defined circumstances or situations require re-authentication.

If the ALG does not require users to re-authenticate when organization-defined circumstances or situations require re-authentication, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to require users to re-authenticate when organization-defined circumstances or situations require re-authentication.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55121r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54505'
  tag rid: 'SV-68751r1_rule'
  tag stig_id: 'SRG-NET-000337-ALG-000096'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-59359r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
