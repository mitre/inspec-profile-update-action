control 'SV-207329' do
  title 'Exchange must not send delivery reports to remote domains.'
  desc 'Attackers can use automated messages to determine whether a user account is active, in the office, traveling, and so on. An attacker might use this information to conduct future attacks. Ensure that delivery reports to remote domains are disabled. Before enabling this setting, first configure a remote domain using the EMC or the New-RemoteDomain cmdlet.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:
 
Get-RemoteDomain | Select Identity, DeliveryReportEnabled

If the value of DeliveryReportEnabled is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -DeliveryReportEnabled $false

Note: The <IdentityName> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7587r393500_chk'
  tag severity: 'medium'
  tag gid: 'V-207329'
  tag rid: 'SV-207329r615936_rule'
  tag stig_id: 'EX13-MB-000315'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-7587r393501_fix'
  tag 'documentable'
  tag legacy: ['SV-84701', 'V-70079']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
