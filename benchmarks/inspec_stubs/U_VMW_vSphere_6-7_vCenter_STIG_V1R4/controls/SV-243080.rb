control 'SV-243080' do
  title 'The vCenter Server must limit the use of the built-in SSO administrative account.'
  desc 'Use of the SSO administrator account should be limited as it is a shared account and individual accounts must be used wherever possible.'
  desc 'check', 'Verify the built-in SSO administrator account is only used for emergencies and situations where it is the only option due to permissions.

If the built-in SSO administrator account is used for daily operations or there is no policy restricting its use, this is a finding.'
  desc 'fix', 'Develop a policy to limit the use of the built-in SSO administrator account.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46355r719481_chk'
  tag severity: 'medium'
  tag gid: 'V-243080'
  tag rid: 'SV-243080r879594_rule'
  tag stig_id: 'VCTR-67-000010'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-46312r719482_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
