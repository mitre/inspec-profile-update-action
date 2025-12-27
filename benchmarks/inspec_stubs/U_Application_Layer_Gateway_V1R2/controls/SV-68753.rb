control 'SV-68753' do
  title 'The ALG providing user access control intermediary services must be configured with a pre-established trust relationship and mechanisms with appropriate authorities (e.g., Active Directory or AAA server) which validate user account access authorizations and privileges.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

ALGs can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on the ALG, particularly if the gateway resides on the untrusted zone of the Enclave.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG is configured with a pre-established trust relationship and mechanisms with appropriate authorities which validate each user access authorization and privileges.

If the ALG is not configured with a pre-established trust relationship and mechanisms with appropriate authorities which validate each user access authorization and privileges, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG with a pre-established trust relationship and mechanisms with appropriate authorities which validate each user access authorization and privileges.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55123r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54507'
  tag rid: 'SV-68753r1_rule'
  tag stig_id: 'SRG-NET-000138-ALG-000088'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-59361r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
