control 'SV-233321' do
  title 'Forescout must enforce the revocation of endpoint access authorizations at the next compliance assessment interval based on changes to the compliance assessment security policy. This is required for compliance with C2C Step 4.'
  desc 'This requirement gives the option to configure for automated remediation and/or manual remediation. A detailed record must be passed to the remediation server for action. Alternatively, the details can be passed in a notice to the user for action. The device status will be updated on the network access server/authentication server so that further access attempts are denied. The NAC must have policy assessment mechanisms with granular control to distinguish between access restrictions based on the criticality of the software or setting failure.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify Forescout admission policy has been configured to revoke access to endpoints that have not met or are removed from the authorized group.

If Forescout is not configured with an admissions policy that enforces the revocation of endpoint access authorizations based on when devices are removed from an authorization group, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure the authorization policy to configured to perform a control action on any devices that have not met authorization requirement or are no longer authorized.

1. Log on to the Forescout UI.
2. From the Policy tab, check that the authorization policy has a Block Action enabled on any devices that have not met or are removed from the authorized group.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36516r811390_chk'
  tag severity: 'medium'
  tag gid: 'V-233321'
  tag rid: 'SV-233321r856507_rule'
  tag stig_id: 'FORE-NC-000130'
  tag gtitle: 'SRG-NET-000322-NAC-001220'
  tag fix_id: 'F-36481r803464_fix'
  tag 'documentable'
  tag cci: ['CCI-002179']
  tag nist: ['AC-3 (8)']
end
