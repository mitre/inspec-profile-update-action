control 'SV-68781' do
  title 'The ALG providing user authentication intermediary services must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

Non-organizational users will be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access. Authorization requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of user identities is accomplished through the use of passwords, tokens, biometrics, or in the case of multifactor authentication, some combination thereof.

This control applies to application layer gateways that provide content filtering and proxy services on network segments (e.g., DMZ) that allow access by non-organizational users. This requirement focuses on authentication requests to the proxied application for access to destination resources and policy filtering decisions rather than administrator and management functions.'
  desc 'check', 'If intermediary services are not provided to non-organizational users, this is not applicable.

If the ALG does not provide user authentication intermediary services, this is not applicable.

Review the ALG authentication functions. Verify identification and authentication is required for non-organizational users.
Examine the policy filters to verify a rule exists to deny access to unauthenticated, non-organizational users.

If the ALG does not uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure ALG to uniquely identify and authenticate non-organizational users or processes acting on behalf of non-organizational users.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55151r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54535'
  tag rid: 'SV-68781r1_rule'
  tag stig_id: 'SRG-NET-000169-ALG-000102'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-59389r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
