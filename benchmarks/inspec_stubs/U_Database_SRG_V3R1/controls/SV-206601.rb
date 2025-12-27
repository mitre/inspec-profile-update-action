control 'SV-206601' do
  title 'The DBMS must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'Review system settings to determine whether the organization-defined limit for cached authentication is implemented.

If it is not implemented, this is a finding.'
  desc 'fix', 'Modify system settings to implement the organization-defined limit on the lifetime of cached authenticators.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6861r291471_chk'
  tag severity: 'medium'
  tag gid: 'V-206601'
  tag rid: 'SV-206601r617447_rule'
  tag stig_id: 'SRG-APP-000400-DB-000367'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-6861r291472_fix'
  tag 'documentable'
  tag legacy: ['V-58137', 'SV-72567']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
