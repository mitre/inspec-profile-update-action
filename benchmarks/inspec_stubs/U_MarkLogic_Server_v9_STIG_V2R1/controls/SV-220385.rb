control 'SV-220385' do
  title 'MarkLogic Server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'Review MarkLogic settings to determine whether the organization-defined limit for cached authentication is implemented.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the External Security icon.
3. Select each of the External Security providers.
4. For each of the providers inspect the cache timeout field, a value that does not match the organization-defined time limit is a finding.'
  desc 'fix', 'Modify MarkLogic settings to implement the organization-defined limit on the lifetime of cached authenticators.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security icon.
2. Click the External Security icon.
3. Select each of the External Security providers.
4. For each of the providers set the cache timeout field to the organization-defined time limit.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22100r401606_chk'
  tag severity: 'medium'
  tag gid: 'V-220385'
  tag rid: 'SV-220385r855490_rule'
  tag stig_id: 'ML09-00-008200'
  tag gtitle: 'SRG-APP-000400-DB-000367'
  tag fix_id: 'F-22089r401607_fix'
  tag 'documentable'
  tag legacy: ['SV-110119', 'V-101015']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
