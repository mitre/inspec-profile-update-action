control 'SV-40067' do
  title 'The system must use a virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration by computer viruses and to limit their spread through intermediate systems.'
  desc 'check', 'The operator will ensure that anti-virus software is installed and operating.

If the operator is unable to provide a documented configuration for an installed anti-virus software system or if not properly used, this is a finding.'
  desc 'fix', 'The operator will ensure that anti-virus software is installed and operating.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-39056r4_chk'
  tag severity: 'medium'
  tag gid: 'V-12765'
  tag rid: 'SV-40067r4_rule'
  tag stig_id: 'GEN006640'
  tag gtitle: 'GEN006640'
  tag fix_id: 'F-12286r5_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
