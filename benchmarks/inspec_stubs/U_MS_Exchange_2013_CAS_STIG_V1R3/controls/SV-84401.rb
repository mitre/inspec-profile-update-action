control 'SV-84401' do
  title 'Exchange must have the most current, approved service pack installed.'
  desc 'Failure to install the most current Exchange service pack leaves a system vulnerable to exploitation. Current service packs correct known security and system vulnerabilities.'
  desc 'check', 'Determine the most current, approved service pack.

Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer | fl Name, AdminDisplayVersion

If the value of AdminDisplayVersion does not return the most current, approved service pack, this is a finding.'
  desc 'fix', 'Install the most current, approved service pack.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69779'
  tag rid: 'SV-84401r1_rule'
  tag stig_id: 'EX13-CA-000160'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-75991r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
