control 'SV-228392' do
  title 'Exchange external/Internet-bound automated response messages must be disabled.'
  desc 'Spam originators, in an effort to refine mailing lists, sometimes monitor transmissions for automated bounce-back messages. Automated messages include such items as "Out of Office" responses, nondelivery messages, and automated message forwarding.

Automated bounce-back messages can be used by a third party to determine if users exist on the server. This can result in the disclosure of active user accounts to third parties, paving the way for possible future attacks.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-RemoteDomain  | Select Name, DomainName, Identity, AllowedOOFType

If the value of "AllowedOOFType" is not set to "InternalLegacy", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-RemoteDomain -Identity <'IdentityName'> -AllowedOOFType 'InternalLegacy'

Note: The <IdentityName> and InternalLegacy values must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30625r496972_chk'
  tag severity: 'medium'
  tag gid: 'V-228392'
  tag rid: 'SV-228392r612748_rule'
  tag stig_id: 'EX16-MB-000480'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30610r496973_fix'
  tag 'documentable'
  tag legacy: ['SV-95409', 'V-80699']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
