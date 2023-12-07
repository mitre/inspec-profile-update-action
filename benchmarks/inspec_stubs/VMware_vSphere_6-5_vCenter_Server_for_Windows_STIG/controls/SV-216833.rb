control 'SV-216833' do
  title 'The vCenter Server for Windows must limit the use of the built-in SSO administrative account.'
  desc 'Use of the SSO administrator account should be limited as it is a shared account and individual accounts must be used wherever possible.'
  desc 'check', 'Verify the built-in SSO administrator account is only used for emergencies and situations where it is the only option due to permissions.

If the built-in SSO administrator account is used for daily operations or there is no policy restricting its use, this is a finding.'
  desc 'fix', 'A policy should be developed to limit the use of the built-in SSO administrator account.'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18064r366213_chk'
  tag severity: 'medium'
  tag gid: 'V-216833'
  tag rid: 'SV-216833r879594_rule'
  tag stig_id: 'VCWN-65-000010'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-18062r366214_fix'
  tag 'documentable'
  tag legacy: ['SV-104563', 'V-94733']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
