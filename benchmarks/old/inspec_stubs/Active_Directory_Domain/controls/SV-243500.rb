control 'SV-243500' do
  title 'Active Directory must be supported by multiple domain controllers where the Risk Management Framework categorization for Availability is moderate or high.'
  desc 'In Active Directory (AD) architecture, multiple domain controllers provide availability through redundancy.  If an AD domain or servers within it have an Availability categorization of medium or high and the domain is supported by only a single domain controller, an outage of that machine can prevent users from accessing resources on servers in that domain and in other AD domains.'
  desc 'check', 'Determine the Availability categorization information for the domain.
If the Availability categorization of the domain is low, this is NA.
If the Availability categorization of the domain is moderate or high, verify the domain is supported by more than one domain controller.
Start "Active Directory Users and Computers" (Available from various menus or run "dsa.msc").
Expand the left pane item that matches the domain being reviewed.
Select the Domain Controllers Organizational Unit (OU) in the left pane.

If there is only one domain controller in the OU, this is a finding.'
  desc 'fix', 'Implement multiple domain controllers in domains with an Availability categorization of moderate or high.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46775r723533_chk'
  tag severity: 'medium'
  tag gid: 'V-243500'
  tag rid: 'SV-243500r723535_rule'
  tag stig_id: 'DS00.6140_AD'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46732r723534_fix'
  tag 'documentable'
  tag legacy: ['V-8524', 'SV-30996']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
