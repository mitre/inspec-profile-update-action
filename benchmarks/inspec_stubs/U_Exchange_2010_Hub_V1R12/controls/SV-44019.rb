control 'SV-44019' do
  title 'Exchange must not send non-delivery reports to remote domains.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Ensure that non-delivery reports to remote domains are disabled. Before enabling this setting first configure a remote domain using the EMC or the New-RemoteDomain cmdlet.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | select identity, NDREnabled

If the value of 'NDREnabled' is not set to 'False', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'RemoteDomainName'> -NDREnabled $false"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41706r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33599'
  tag rid: 'SV-44019r1_rule'
  tag stig_id: 'Exch-2-808'
  tag gtitle: 'Exch-2-808'
  tag fix_id: 'F-37491r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
