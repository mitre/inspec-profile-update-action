control 'SV-215764' do
  title 'The BIG-IP Core implementation must be configured to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users) when connecting to virtual servers.'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

Non-organizational users will be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access. Authorization requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of user identities is accomplished through the use of passwords, tokens, biometrics, or in the case of multifactor authentication, some combination thereof.

This control applies to application layer gateways that provide content filtering and proxy services on network segments (e.g., DMZ) that allow access by non-organizational users. This requirement focuses on authentication requests to the proxied application for access to destination resources and policy filtering decisions rather than administrator and management functions.'
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, review the BIG-IP LTM module authentication functions to verify identification and authentication are required for non-organizational users.

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users) when connecting to virtual servers.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

If the BIG-IP Core does not uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users) when connecting to virtual servers, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).

Apply APM policy to the applicable Virtual Server(s) in BIG-IP LTM module to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users) when connecting to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16956r291105_chk'
  tag severity: 'medium'
  tag gid: 'V-215764'
  tag rid: 'SV-215764r557356_rule'
  tag stig_id: 'F5BI-LT-000087'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-16954r291106_fix'
  tag 'documentable'
  tag legacy: ['SV-74739', 'V-60309']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
