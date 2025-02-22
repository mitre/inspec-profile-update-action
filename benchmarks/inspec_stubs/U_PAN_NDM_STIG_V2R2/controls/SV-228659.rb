control 'SV-228659' do
  title 'Administrators in the role of Security Administrator,  Cryptographic Administrator, or Audit Administrator must not also have the role of Audit Administrator.'
  desc 'The Palo Alto Networks security platform has both pre-configured and configurable Administrator roles. Administrator roles determine the functions that the administrator is permitted to perform after logging in. Roles can be assigned directly to an administrator account, or define role profiles, which specify detailed privileges, and assign those to administrator accounts.

There are three preconfigured roles designed to comply with Common Criteria requirements - Security Administrator, Audit Administrator, and Cryptographic Administrator. Of the three, only the Audit Administrator can delete audit records.  The Palo Alto Networks security platform can use both pre-configured and configurable Administrator roles.'
  desc 'check', 'For the roles of Security Administrator, Cryptographic Administrator, or Audit Administators, verify the same individual does not have more than one of these roles.

If the Palo Alto Networks security platform has any accounts where the same person is in the role of Security Administrator, Cryptographic Administrator, or Audit Administrator, this is a finding.'
  desc 'fix', 'Do not assign or configure more than one account to the same Administrator. Also, neither the Security Administrator nor the Cryptographic Administrator can be have the role of Audit Administrator.

Note that the system allows each account to have only one role assigned. However, individuals, either accidentally or intentionally, may have more than one account.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30894r864174_chk'
  tag severity: 'medium'
  tag gid: 'V-228659'
  tag rid: 'SV-228659r864176_rule'
  tag stig_id: 'PANW-NM-000075'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-30871r864175_fix'
  tag 'documentable'
  tag legacy: ['SV-77235', 'V-62745']
  tag cci: ['CCI-000366', 'CCI-001314']
  tag nist: ['CM-6 b', 'SI-11 b']
end
