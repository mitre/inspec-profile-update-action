control 'SV-233320' do
  title 'Forescout must enforce the revocation of endpoint access authorizations when devices are removed from an authorization group. This is required for compliance with C2C Step 4.'
  desc 'Ensuring the conditions that are configured in policy have proper time limits set to reflect changes will allow for proper access. This will help to validate that authorized individuals have proper access.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify Forescout admission policy has been configured to revoke access to endpoints that have not met or are removed from the authorized group.

If Forescout is not configured with an admissions policy that enforces the revocation of endpoint access authorizations based on when devices are removed from an authorization group, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure the authorization policy to take a control action on any devices that have not met authorization requirement or are no longer authorized.

1. Log on to the Forescout UI.
2. From the Policy tab, check that the authorization policy has a Block Action enabled on any devices that have not met or are removed from the authorized group.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36515r811388_chk'
  tag severity: 'medium'
  tag gid: 'V-233320'
  tag rid: 'SV-233320r856506_rule'
  tag stig_id: 'FORE-NC-000120'
  tag gtitle: 'SRG-NET-000321-NAC-001210'
  tag fix_id: 'F-36480r803462_fix'
  tag 'documentable'
  tag cci: ['CCI-002178']
  tag nist: ['AC-3 (8)']
end
