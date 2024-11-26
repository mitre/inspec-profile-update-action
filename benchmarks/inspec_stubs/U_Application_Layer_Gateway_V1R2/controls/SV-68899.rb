control 'SV-68899' do
  title 'The ALG providing content filtering must automatically update malicious code protection mechanisms.'
  desc 'The malicious software detection functionality on network elements needs to be constantly updated in order to identify new threats as they are discovered.

All malicious software detection functions must come with an update mechanism that automatically updates the application and any associated signature definitions. The organization (including any contractor to the organization) is required to promptly install security-relevant malicious code protection updates. Examples of relevant updates include anti-virus signatures, detection heuristic rule sets, and/or file reputation data employed to identify and/or block malicious software from executing.

Malicious code includes viruses, worms, Trojan horses, and Spyware.

This requirement is limited to ALGs, web content filters, and packet inspection firewalls that perform malicious code detection as part of their functionality.'
  desc 'check', 'If the ALG does not perform content filtering as part of its traffic management functionality, this is not applicable.

Verify the ALG automatically updates malicious code protection mechanisms.

If the ALG does not automatically update malicious code protection mechanisms, this is a finding.'
  desc 'fix', 'If the ALG performs content filtering as part of the traffic management functionality, configure the ALG to automatically update malicious code protection mechanisms.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55273r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54653'
  tag rid: 'SV-68899r1_rule'
  tag stig_id: 'SRG-NET-000251-ALG-000131'
  tag gtitle: 'SRG-NET-000251-ALG-000131'
  tag fix_id: 'F-59509r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001247']
  tag nist: ['SI-3 (2)']
end
