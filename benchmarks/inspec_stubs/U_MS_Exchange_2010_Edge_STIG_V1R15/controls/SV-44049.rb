control 'SV-44049' do
  title 'The current, approved service pack must be installed.'
  desc 'Failure to install the most current Exchange service pack leaves a system vulnerable to exploitation. Current service packs correct known security and system vulnerabilities.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer | fl name, AdminDisplayVersion

If the value of 'AdminDisplayVersion' does not return Version 14.2 (Build 247.5) or greater, this is a finding."
  desc 'fix', 'Update the system with the latest approved service pack or a supported release.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41737r5_chk'
  tag severity: 'medium'
  tag gid: 'V-33629'
  tag rid: 'SV-44049r3_rule'
  tag stig_id: 'Exch-3-814'
  tag gtitle: 'Exch-3-814'
  tag fix_id: 'F-37521r3_fix'
  tag 'documentable'
end
