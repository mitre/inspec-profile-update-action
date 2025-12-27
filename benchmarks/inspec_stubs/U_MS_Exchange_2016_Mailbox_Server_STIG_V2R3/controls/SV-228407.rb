control 'SV-228407' do
  title 'Exchange must not send nondelivery reports to remote domains.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Ensure that nondelivery reports to remote domains are disabled. Before enabling this setting, first configure a remote domain using the Exchange Management Console (EMC) or the New-RemoteDomain cmdlet.'
  desc 'check', 'NOTE: For the purpose of this requirement, “remote” refers to those domains external to the DoDIN, whether classified or unclassified. NDRs between DoDIN networks is permitted.

Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain | Select Name, Identity, NDREnabled

If the value of "NDREnabled" is not set to "False", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -NDREnabled $false

Note: The <IdentityName> value must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30640r684254_chk'
  tag severity: 'medium'
  tag gid: 'V-228407'
  tag rid: 'SV-228407r684255_rule'
  tag stig_id: 'EX16-MB-000640'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-30625r497018_fix'
  tag 'documentable'
  tag legacy: ['SV-95457', 'V-80747']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
