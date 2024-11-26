control 'SV-221263' do
  title 'Exchange must have the most current, approved service pack installed.'
  desc 'The organization (including any contractor to the organization) must promptly install security-relevant software updates (e.g., patches, service packs, hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer | fl name, AdminDisplayVersion

If the value of "AdminDisplayVersion" does not return the most current, approved service pack, this is a finding.'
  desc 'fix', 'Install the most current, approved service pack.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22978r411915_chk'
  tag severity: 'medium'
  tag gid: 'V-221263'
  tag rid: 'SV-221263r612603_rule'
  tag stig_id: 'EX16-ED-000700'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-22967r411916_fix'
  tag 'documentable'
  tag legacy: ['V-80605', 'SV-95315']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
