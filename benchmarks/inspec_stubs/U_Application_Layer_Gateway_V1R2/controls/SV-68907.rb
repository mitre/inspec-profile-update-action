control 'SV-68907' do
  title 'The ALG providing content filtering must delete or quarantine malicious code in response to malicious code detection.'
  desc 'Taking an appropriate action based on local organizational incident handling procedures minimizes the impact of this code on the network.

The ALG must be configured to block all detected malicious code. It is sometimes acceptable/necessary to generate a log event and then automatically delete the malicious code; however for critical attacks or where forensic evidence is deemed necessary, the file should be quarantined for further investigation.

This requirement is limited to ALGs web content filters and packet inspection firewalls; that perform malicious code detection as part of their functionality.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functionality, this is not applicable.

Verify the ALG blocks and either deletes or quarantines malicious code upon detection.

If the ALG does not block and either delete or quarantine malicious code upon detection, this is a finding.'
  desc 'fix', 'If content filtering is provided as part of the traffic management functionality, configure the ALG to block and either delete or quarantine malicious code when it is detected.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55281r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54661'
  tag rid: 'SV-68907r1_rule'
  tag stig_id: 'SRG-NET-000249-ALG-000145'
  tag gtitle: 'SRG-NET-000249-ALG-000145'
  tag fix_id: 'F-59517r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
