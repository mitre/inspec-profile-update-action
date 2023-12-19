control 'SV-228356' do
  title 'Exchange auto-forwarding email to remote domains must be disabled or restricted.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Verify Automatic Forwards to remote domains are disabled, except for enterprise mail that must be restricted to forward only to .mil and .gov. domains.

Before enabling this setting, configure a remote domain.'
  desc 'check', 'Note: Requirement is not applicable on classified or completely closed networks.

Non-Enterprise Mail Check Content: 

Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | Select Identity, AutoForwardEnabled

If the value of AutoForwardEnabled is not set to "False", this is a finding.

Enterprise Mail Check Content:

If the value of "AutoForwardEnabled" is set to "True", this is not a finding.

and 

In the Exchange Management Shell, enter the following command:

Get-RemoteDomain

If the value of "RemoteDomain" is not set to ".mil" and/or ".gov" domain(s), this is a finding.'
  desc 'fix', "Non-Enterprise Mail Fix Text:

Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -AutoForwardEnabled $false 

Note: The <IdentityName> value must be in single quotes.

Enterprise Mail Fix Text:

New-RemoteDomain -Name <NewRemoteDomainName> -DomainName <SMTP Address>

Note: <NewRemoteDomainName> must either be a .mil or .gov domain.

Set-RemoteDomain -Identity <'RemoteDomainIdentity'> -AutoForwardEnabled $true

Note: The <RemoteDomainIdentity> value must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30589r622502_chk'
  tag severity: 'medium'
  tag gid: 'V-228356'
  tag rid: 'SV-228356r612748_rule'
  tag stig_id: 'EX16-MB-000030'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-30574r496865_fix'
  tag 'documentable'
  tag legacy: ['SV-95337', 'V-80627']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
