control 'SV-44053' do
  title 'Block list service provider must be identified.'
  desc "Block List filtering is a sanitization process performed on email messages prior to their arrival at the destination mailbox.  By performing this process at the email perimeter, threats can be eliminated outside the enclave, where there is less risk they can do harm.   
 
Block List Services (sometimes called Reputation Data Services) are fee based data providers that collect the IP addresses of known SPAMmers and other malware purveyors.  Block List Service Subscribers benefit from more effective SPAM elimination, which has been estimated as comprising up to 90% of inbound mail volume.  Failure to specify a Block List provider risks that manual email administration effort would be needed to maintain and update larger block lists than a single email site administrator could conveniently or accurately maintain. 

The 'Block List' Services vendor provides a value for this field, usually the DNS suffix for their domain."
  desc 'check', 'Access the EDSP for the name and information for the Block List provider.   

Open the Exchange Management Shell and enter the following command:
Get-IPBlockListProvider | Select Name Identity LookupDomain

If the values for Name, GUID and LookupDomain are configured, this is not a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-IPBlockListProvider -Name <Provider Name> [Additional optional parameters as required by the service provider]

Document the configuration in the EDSP.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41742r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33633'
  tag rid: 'SV-44053r2_rule'
  tag stig_id: 'Exch-2-330'
  tag gtitle: 'Exch-2-330'
  tag fix_id: 'F-37525r2_fix'
  tag 'documentable'
end
