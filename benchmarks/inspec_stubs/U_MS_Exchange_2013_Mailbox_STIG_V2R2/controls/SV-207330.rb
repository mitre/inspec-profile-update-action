control 'SV-207330' do
  title 'Exchange must not send nondelivery reports to remote domains.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Ensure that nondelivery reports to remote domains are disabled. Before enabling this setting, first configure a remote domain using the EMC or the New-RemoteDomain cmdlet.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | Select Name, Identity, NDREnabled

If the value of NDREnabled is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -NDREnabled $false

Note: The <IdentityName> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7588r393503_chk'
  tag severity: 'medium'
  tag gid: 'V-207330'
  tag rid: 'SV-207330r615936_rule'
  tag stig_id: 'EX13-MB-000320'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-7588r393504_fix'
  tag 'documentable'
  tag legacy: ['SV-84703', 'V-70081']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
