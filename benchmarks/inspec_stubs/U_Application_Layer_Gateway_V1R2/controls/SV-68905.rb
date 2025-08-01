control 'SV-68905' do
  title 'The ALG providing content filtering must block malicious code upon detection.'
  desc 'Taking an appropriate action based on local organizational incident handling procedures minimizes the impact of this code on the network.

This requirement is limited to ALGs web content filters and packet inspection firewalls; that perform malicious code detection as part of their functionality.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functionality, this is not applicable.

Verify the ALG blocks malicious code upon detection.

If the ALG does not block malicious code when detected, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of its traffic management functionality, configure the ALG to block malicious code upon detection.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55279r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54659'
  tag rid: 'SV-68905r1_rule'
  tag stig_id: 'SRG-NET-000249-ALG-000134'
  tag gtitle: 'SRG-NET-000249-ALG-000134'
  tag fix_id: 'F-59515r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
