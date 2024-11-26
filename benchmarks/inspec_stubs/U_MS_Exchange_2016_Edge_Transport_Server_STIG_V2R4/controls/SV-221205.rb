control 'SV-221205' do
  title 'Exchange must have auto-forwarding of email to remote domains disabled or restricted.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Ensure Automatic Forwards to remote domains are disabled, except for enterprise email that must be restricted to forward-only to .mil and .gov. domains.

Before enabling this setting, first configure a remote domain.'
  desc 'check', 'Non-Enterprise Mail Check Content: 

Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | Select Name, DomainName, Identity, AutoForwardEnabled

If the value of "AutoForwardEnabled" is not set to "False", this is a finding.

Enterprise Mail Check Content:

Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | Select Name, DomainName, Identity, AutoForwardEnabled

If the value of “AutoForwardEnabled” is “True” and “DomainName” is not set to a “.mil” and/or “.gov” domain(s), this is a finding.'
  desc 'fix', %q(For Non-Enterprise Mail Fix Text:

Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -AutoForwardEnabled $false 

Note: The <IdentityName> value must be in single quotes.

For Enterprise Mail Fix Text, enter the following commands:

New-RemoteDomain -Name <NewDomainName> -DomainName <SMTP address space>

Note: NewDomainName must be either a ".mil" or ".gov" domain.

Set-RemoteDomain -Identity <'IdentityName'> -AutoForwardEnabled $true)
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22920r411741_chk'
  tag severity: 'medium'
  tag gid: 'V-221205'
  tag rid: 'SV-221205r612603_rule'
  tag stig_id: 'EX16-ED-000040'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-22909r411742_fix'
  tag 'documentable'
  tag legacy: ['SV-95201', 'V-80491']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
