control 'SV-84557' do
  title 'Exchange must have the most current, approved service pack installed.'
  desc 'The organization (including any contractor to the organization) must promptly install security-relevant software updates (e.g., patches, service packs, hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer | fl name, AdminDisplayVersion

If the value of AdminDisplayVersion does not return the most current, approved service pack, this is a finding.'
  desc 'fix', 'Install the most current, approved service pack.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70405r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69935'
  tag rid: 'SV-84557r1_rule'
  tag stig_id: 'EX13-EG-000350'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-76167r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
