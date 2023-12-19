control 'SV-104235' do
  title 'Symantec ProxySG must be configured with a pre-established trust relationship and mechanisms with appropriate authorities that validate user account access authorizations and privileges.'
  desc 'User account and privilege validation must be centralized to prevent unauthorized access using changed or revoked privileges.

ALGs can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on the ALG, particularly if the gateway resides on the untrusted zone of the enclave.'
  desc 'check', 'Verify that the ProxySG is configured with pre-established trust relationships with the appropriate authorities.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.

If Symantec ProxySG is not configured with a pre-established trust relationship and mechanisms with appropriate authorities that validate user account access authorizations and privileges, this is a finding.'
  desc 'fix', 'Configure the ProxySG with pre-established trust relationships with the appropriate authorities.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication >> Windows Domain.
3. Click "Add New Domain" and follow prompts to join the Windows Domain.'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93467r1_chk'
  tag severity: 'high'
  tag gid: 'V-94281'
  tag rid: 'SV-104235r1_rule'
  tag stig_id: 'SYMP-AG-000330'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-100397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
