control 'SV-36041' do
  title 'MDM server administrator training must be renewed annually.'
  desc 'The MDM server administrator must renew required training annually.'
  desc 'check', 'The site should document when training was completed.

-Verify training is renewed annually.

If the MDM server administrator training is not renewed annually, this is a finding.'
  desc 'fix', 'Renew required training annually.'
  impact 0.3
  ref 'DPMS Target MDM Server Policy'
  tag check_id: 'C-35162r6_chk'
  tag severity: 'low'
  tag gid: 'V-28313'
  tag rid: 'SV-36041r6_rule'
  tag stig_id: 'WIR-WMSP-001-02'
  tag gtitle: 'MDM server administrator training renewed annually'
  tag fix_id: 'F-30410r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
