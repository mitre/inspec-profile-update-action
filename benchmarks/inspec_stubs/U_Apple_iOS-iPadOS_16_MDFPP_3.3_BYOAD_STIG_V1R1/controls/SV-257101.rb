control 'SV-257101' do
  title 'The User Agreement must include a description of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools.'
  desc 'DOD policy states BYOAD owners must sign a user agreement and be made aware of what personal data and activities will be monitored by the enterprise by including this information in the user agreement.

Reference: DOD policy "Use of Non-Government Mobile Devices" 3.a.(3)ii, and 3.c.(4).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the user agreement includes a description of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools.

If the user agreement does not include a description of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools, this is a finding.'
  desc 'fix', 'Include a description in the user agreement of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools.'
  impact 0.3
  ref 'DPMS Target Apple iOS-iPadOS 16 MDFPP 3.3 BYOAD'
  tag check_id: 'C-60786r904046_chk'
  tag severity: 'low'
  tag gid: 'V-257101'
  tag rid: 'SV-257101r904048_rule'
  tag stig_id: 'AIOS-16-800210'
  tag gtitle: 'PP-BYO-000210'
  tag fix_id: 'F-60727r904047_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
