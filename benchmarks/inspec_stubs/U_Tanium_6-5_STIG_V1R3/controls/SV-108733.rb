control 'SV-108733' do
  title 'Tanium version must be greater than version 7.'
  desc 'Tanium version 6.5 is end of life and out of vendor support.'
  desc 'check', 'Validate Tanium version. 

If running version 6.5, this is a finding.'
  desc 'fix', 'Upgrade to Tanium 7 or higher.'
  impact 0.7
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-98479r1_chk'
  tag severity: 'high'
  tag gid: 'V-99629'
  tag rid: 'SV-108733r1_rule'
  tag stig_id: 'TANS-SV-000050'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-105313r1_fix'
  tag 'documentable'
end
