control 'SV-77235' do
  title 'Administrators in the role of either Security Administrator or Cryptographic Administrator must not also have the role of Audit Administrator.'
  desc 'The Palo Alto Networks security platform has both pre-configured and configurable Administrator roles. Administrator roles determine the functions that the administrator is permitted to perform after logging in. Roles can be assigned directly to an administrator account, or define role profiles, which specify detailed privileges, and assign those to administrator accounts.

There are three preconfigured roles designed to comply with Common Criteria requirements - Security Administrator, Audit Administrator, and Cryptographic Administrator. Of the three, only the Audit Administrator can delete audit records.  The Palo Alto Networks security platform can use both pre-configured and configurable Administrator roles.'
  desc 'check', 'If the Palo Alto Networks security platform has any accounts where the same person is in the role of both Security Administrator and Cryptographic Administrator, this is a finding.

Note: Each account can only have one role, but individuals, either accidentally or intentionally, may have more than one account.'
  desc 'fix', 'Do not assign or configure more than one account to the same Administrator.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63553r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62745'
  tag rid: 'SV-77235r1_rule'
  tag stig_id: 'PANW-NM-000075'
  tag gtitle: 'SRG-APP-000267-NDM-000273'
  tag fix_id: 'F-68665r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
