control 'SV-215723' do
  title 'The BIG-IP APM module must be configured to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users) when connecting to virtual servers.'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

Non-organizational users will be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access. Authorization requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of user identities is accomplished through the use of passwords, tokens, biometrics, or in the case of multifactor authentication, some combination thereof.

This control applies to application layer gateways that provide content filtering and proxy services on network segments (e.g., DMZ) that allow access by non-organizational users. This requirement focuses on authentication requests to the proxied application for access to destination resources and policy filtering decisions rather than administrator and management functions.'
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services to non-organizational users, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used to identify and authenticate non-organizational users.

Verify the Access Profile is configured to uniquely identify and authenticate non-organizational users.

If the BIG-IP APM module is not configured to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users) when connecting to virtual servers, this is a finding.'
  desc 'fix', 'If the BIG-IP APM module provides user authentication intermediary services to non-organizational users, configure a profile in the BIG-IP APM module to uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users) when connecting to virtual servers.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16916r290415_chk'
  tag severity: 'medium'
  tag gid: 'V-215723'
  tag rid: 'SV-215723r557355_rule'
  tag stig_id: 'F5BI-AP-000087'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-16914r290416_fix'
  tag 'documentable'
  tag legacy: ['V-60037', 'SV-74467']
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
