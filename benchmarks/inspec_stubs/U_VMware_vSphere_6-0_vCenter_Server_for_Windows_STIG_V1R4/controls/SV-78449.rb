control 'SV-78449' do
  title 'The system must limit the use of the built-in SSO administrative account.'
  desc 'Use of the SSO administrator account should be limited as it is a shared account and individual accounts must be used wherever possible.'
  desc 'check', 'Verify the built-in SSO administrator account is only used for emergencies and situations where it is the only option due to permissions.

If the built-in SSO administrator account is used for daily operations or there is no policy restricting its use, this is a finding.'
  desc 'fix', 'A policy should be developed to limit the use of the built-in SSO administrator account.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63959'
  tag rid: 'SV-78449r1_rule'
  tag stig_id: 'VCWN-06-000010'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-69889r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
