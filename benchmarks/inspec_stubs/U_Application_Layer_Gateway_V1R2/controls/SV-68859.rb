control 'SV-68859' do
  title 'The ALG providing content filtering must prevent the download of prohibited mobile code.'
  desc 'Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient.

This applies to mobile code that may originate either internal to or external from the enclave. Mobile code is defined as software modules obtained from remote systems, transferred across a network, and then downloaded and executed on a local system without explicit installation or execution by the recipient. Mobile code which must be prevented from downloading is identified in CCI-001166.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functions, this is not applicable.

Verify the ALG prevents the download of prohibited mobile code.

If the ALG does not prevent the download of prohibited mobile code, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to prevent the download of prohibited mobile code.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54613'
  tag rid: 'SV-68859r1_rule'
  tag stig_id: 'SRG-NET-000289-ALG-000110'
  tag gtitle: 'SRG-NET-000289-ALG-000110'
  tag fix_id: 'F-59469r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
