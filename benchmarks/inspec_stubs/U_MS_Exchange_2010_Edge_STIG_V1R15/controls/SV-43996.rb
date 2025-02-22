control 'SV-43996' do
  title 'Auto-forwarding email to remote domains must be disabled or restricted.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Ensure Automatic Forwards to remote domains are disabled, except for enterprise mail that must be restricted to forward-only to .mil and .gov. domains.

Before enabling this setting first configure a remote domain.'
  desc 'check', "Non- Enterprise Mail Check Content: 

Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | select identity, AutoForwardEnabled

If the value of 'AutoForwardEnabled' is not set to 'False', this is a finding.

Enterprise Mail Check Content:

If the value of 'AutoForwardEnabled' is set to 'True', this is not a finding.

and 

In the Exchange Management Shell and enter the following command:

Get-RemoteDomain

If the value of  'RemoteDomain ' is not set to a ' .mil' and/or '.gov ' domain(s), this is a finding."
  desc 'fix', "Non- Enterprise Mail Fix Text:

Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'RemoteDomainName'> -AutoForwardEnabled $false 

Enterprise Mail Fix Text:

New-RemoteDomain -Name <Descriptive Name> -DomainName <SMTP address space>

Set-RemoteDomain -Identity <'RemoteDomainName'> -AutoForwardEnabled $true"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41682r6_chk'
  tag severity: 'medium'
  tag gid: 'V-33576'
  tag rid: 'SV-43996r2_rule'
  tag stig_id: 'Exch-2-736'
  tag gtitle: 'Exch-2-736'
  tag fix_id: 'F-37467r3_fix'
  tag 'documentable'
end
