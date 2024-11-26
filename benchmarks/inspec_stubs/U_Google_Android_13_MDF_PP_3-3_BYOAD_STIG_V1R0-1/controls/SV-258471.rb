control 'SV-258471' do
  title 'The User Agreement must include a description of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools.'
  desc 'DOD policy states BYOAD owners must sign a user agreement and be made aware of what personal data and activities will be monitored by the Enterprise by including this information in the user agreement.

Reference: DOD policy "Use of Non-Government Mobile Devices" (3.a.(3)ii, and 3.c.(4)).

SFR ID: FMT_SMF_EXT.1.1 #47'
  desc 'check', 'Verify the user agreement includes a description of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools.

If the user agreement does not include a description of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools, this is a finding.'
  desc 'fix', 'Include a description of what personal data and information is being monitored, collected, or managed by the EMM system or deployed agents or tools in the user agreement.'
  impact 0.3
  ref 'DPMS Target Google Android 13 MDFPP 3.3 BYOAD'
  tag check_id: 'C-62211r929227_chk'
  tag severity: 'low'
  tag gid: 'V-258471'
  tag rid: 'SV-258471r929229_rule'
  tag stig_id: 'GOOG-13-802100'
  tag gtitle: 'PP-BYO-000210'
  tag fix_id: 'F-62120r929228_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
