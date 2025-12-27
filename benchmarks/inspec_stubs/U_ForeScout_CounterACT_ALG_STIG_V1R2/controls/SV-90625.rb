control 'SV-90625' do
  title 'If user authentication services are provided, CounterACT must be configured with a pre-established trust relationship and mechanisms with a central directory service that validates user account access authorizations and privileges.'
  desc 'User account and privilege validation must be centralized in order to prevent unauthorized access using changed or revoked privileges.

CounterACT can implement functions such as traffic filtering, authentication, access, and authorization functions based on computer and user privileges. However, the directory service (e.g., Active Directory or LDAP) must not be installed on CounterACT, particularly if the gateway resides on the untrusted zone of the Enclave.'
  desc 'check', 'If CounterACT does not provide user authentication intermediary services, this is not applicable.

Verify CounterACT is configured for NAC services authentication.

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> User Directory.
3. Verify the User Directory configured for Authentication. Select the configured directory (or directories) and on the General Tab ensure the "Use for Authentication" radio button is selected. 

Verify with site representatives that the directory service validates user account access authorizations and privileges. 

If CounterACT does not use a central directory service to validate user account access authorizations and privileges, this is a finding.'
  desc 'fix', 'If user authentication service is provided by CounterACT, configure the use of a central directory service for user authentication.

Obtain configuration information for a directory service (e.g., Active Directory or LDAP) that validates user account access authorizations and privileges.

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> User Directory.
3. Verify the User Directory configured for Authentication. Select the configured directory (or directories) and on the General Tab ensure the "Use for Authentication" radio button is selected.'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75937'
  tag rid: 'SV-90625r1_rule'
  tag stig_id: 'CACT-AG-000006'
  tag gtitle: 'SRG-NET-000138-ALG-000088'
  tag fix_id: 'F-82575r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
