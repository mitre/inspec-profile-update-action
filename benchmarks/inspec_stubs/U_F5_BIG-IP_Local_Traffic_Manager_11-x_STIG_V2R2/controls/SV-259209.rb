control 'SV-259209' do
  title 'The F5 BIG-IP Core implementation must be configured to set a "Maximum Session Timeout" value of 24 hours or less for the virtual server.'
  desc %q(Without reauthentication, users may access resources or perform tasks for which authorization has been removed. The "Maximum Session Timeout" setting configures a limit on the maximum amount of time a user's session is active without needing to reauthenticate. If the value is set to 0 (zero), the user's session is active until either the user terminates the session or the "Inactivity Timeout" value is reached (the default value is set to 604,800 seconds). When determining how long the maximum user session can last, it may be useful to review the access policy.

The default value for "Maximum Session Timeout" is set to 604,800 seconds or 7 days. DOD has deemed this to be excessive because it gives a lengthy period when a valid session is opened, allowing time for attackers to try various methods to gain access to the session. It is very likely that the session idle timeout will disconnect the session; however, this is a defense-in-depth configuration.)
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services virtual servers, this is not applicable.

Navigate to Access >> Profiles/Policies. Select a profile for user sessions.

Verify the BIG-IP Core is configured for a "Maximum Session Timeout" value of 24 hours or less 

If the BIG-IP Core is not set to a "Maximum Session Timeout" value of 24 hours or less, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to set a "Maximum Session Timeout" value of 24 hours or less

Apply the APM policy to the applicable virtual server(s) in the BIG-IP LTM module.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-62948r939131_chk'
  tag severity: 'medium'
  tag gid: 'V-259209'
  tag rid: 'SV-259209r939146_rule'
  tag stig_id: 'F5BI-LT-000310'
  tag gtitle: 'SRG-NET-000337-ALG-000096'
  tag fix_id: 'F-62857r939132_fix'
  tag 'documentable'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
