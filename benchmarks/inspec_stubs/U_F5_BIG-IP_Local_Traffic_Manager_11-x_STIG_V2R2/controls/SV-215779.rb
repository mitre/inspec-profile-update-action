control 'SV-215779' do
  title "The BIG-IP Core implementation must require users to reauthenticate when the user's role, the information authorizations, and/or the maximum session timeout is exceeded for the virtual server(s)."
  desc 'Without reauthentication, users may access resources or perform tasks for which authorization has been removed.

In addition to the reauthentication requirements associated with session locks, organizations may require reauthentication of individuals and/or devices in other situations. Within the DOD, the minimum circumstances requiring reauthentication are privilege escalation, idle timeout, maximum session timeout, and/or role changes.'
  desc 'check', %q(If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to require users to reauthenticate when required by organization-defined circumstances or situations.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section that "Access Policy" has been set to use an APM access policy that requires users to reauthenticate to virtual servers when the user's role, the information authorizations, and/or the maximum session timeout is exceeded for the virtual server(s).

If the BIG-IP Core is not configured to require users to reauthenticate when the user's role, the information authorizations, and/or the maximum session timeout is exceeded for the virtual server(s), this is a finding.)
  desc 'fix', "If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to reauthenticate when the user's role, the information authorizations, and/or the maximum session timeout is exceeded for the virtual server(s).

Apply APM policy to the applicable virtual server(s) in the BIG-IP LTM module."
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16971r939124_chk'
  tag severity: 'medium'
  tag gid: 'V-215779'
  tag rid: 'SV-215779r939150_rule'
  tag stig_id: 'F5BI-LT-000191'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-16969r939125_fix'
  tag 'documentable'
  tag legacy: ['SV-74769', 'V-60339']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
