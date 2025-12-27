control 'SV-68901' do
  title 'The ALG providing content filtering must update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  desc 'Malicious code protection mechanisms include, but are not limited to, anti-virus and malware detection software. In order to minimize any potential negative impact to the organization caused by malicious code, malicious code must be identified and eradicated. Malicious code includes viruses, worms, Trojan horses, and Spyware.

This requirement is limited to ALGs, web content filters, and packet inspection firewalls that perform malicious code detection as part of their functionality.'
  desc 'check', 'If the ALG does not perform content filtering as part of the traffic management functionality, this is not applicable.

Verify the ALG updates malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policy and procedures.

If the ALG does not update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policy and procedures, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to update malicious code protection mechanisms and signature definitions whenever new releases are available in accordance with organizational configuration management policy and procedures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55275r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54655'
  tag rid: 'SV-68901r1_rule'
  tag stig_id: 'SRG-NET-000246-ALG-000132'
  tag gtitle: 'SRG-NET-000246-ALG-000132'
  tag fix_id: 'F-59511r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001240']
  tag nist: ['SI-3 b']
end
