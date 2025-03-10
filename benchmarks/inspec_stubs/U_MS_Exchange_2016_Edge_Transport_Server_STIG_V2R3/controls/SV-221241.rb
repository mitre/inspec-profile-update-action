control 'SV-221241' do
  title 'The Exchange Block List service provider must be identified.'
  desc 'Block List filtering is a sanitization process performed on email messages prior to their arrival at the destination mailbox. By performing this process at the email perimeter, threats can be eliminated outside the enclave, where there is less risk for them to do harm.
 
Block List services (sometimes called Reputation Data services) are fee-based data providers that collect the IP addresses of known spammers and other malware purveyors. Block List service subscribers benefit from more effective spam elimination. (Spam is estimated to compose up to 90 percent of inbound mail volume.) Failure to specify a Block List provider risks that manual email administration effort would be needed to maintain and update larger Block Lists than a single email site administrator could conveniently or accurately maintain. 

The Block List service vendor provides a value for this field, usually the Domain Name System (DNS) suffix for its domain.'
  desc 'check', 'If not using a service provider, this requirement is not applicable. 

Review the Email Domain Security Plan (EDSP).

Determine the name and information for the Block List provider.   

Open the Exchange Management Shell and enter the following command:

Get-IPBlockListProvider | Select Name, Identity, LookupDomain

If the values for "Name", GUID, and "LookupDomain" are not configured, this is a finding.'
  desc 'fix', 'Update the EDSP to reflect the name and information for the Block List provider.

Open the Exchange Management Shell and enter the following command:

Set-IPBlockListProvider -Name <Provider Name> [Additional optional parameters as required by the service provider]'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22956r411849_chk'
  tag severity: 'medium'
  tag gid: 'V-221241'
  tag rid: 'SV-221241r612603_rule'
  tag stig_id: 'EX16-ED-000420'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22945r411850_fix'
  tag 'documentable'
  tag legacy: ['SV-95273', 'V-80563']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
