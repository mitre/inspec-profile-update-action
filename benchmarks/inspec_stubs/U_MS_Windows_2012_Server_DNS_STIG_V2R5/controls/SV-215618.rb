control 'SV-215618' do
  title 'The Name Resolution Policy Table (NRPT) must be configured in Group Policy to enforce clients to request DNSSEC validation for a domain.'
  desc 'The Name Resolution Policy Table (NRPT) is used to require DNSSEC validation. The NRPT can be configured in local Group Policy for a single computer or domain Group Policy for some or all computers in the domain.'
  desc 'check', 'Note: This check is Not applicable for Windows 2012 DNS Servers that only host Active Directory integrated zones or for Windows 2012 DNS servers on a Classified network.

The Name Resolution Policy Table (NRPT) is configured in, and deployed to clients from, Group Policy and will be pushed to all clients in the domain. The Active Directory zones will be signed and the clients, with NRPT, will require a validation of signed data when querying.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

At the Windows PowerShell prompt, type the following command:

get-dnsclientnrptpolicy <enter>

In the results, verify the "DnsSecValidationRequired" is True.

If there are no results to the get-dnsclientnrptpolicy cmdlet or the "DnsSecValidationRequired" is not True, this is a finding.'
  desc 'fix', 'Implement this fix for configuring name resolvers, to include DNS servers configured for caching role only.

On Domain Controller, on the Server Manager menu bar, click Tools, and then click Group Policy Management.

In the Group Policy Management console tree, under Domains >; domainname >; Group Policy Objects, right-click Default Domain Policy, and then click Edit.

In the Group Policy Management Editor console tree, navigate to Computer Configuration >; Policies >; Windows Settings >; Name Resolution Policy.

In the details pane, under Create Rules and to which part of the namespace does this rule apply, choose Suffix from the drop-down list and type domain.mil next to Suffix.
 
On the DNSSEC tab, select the Enable DNSSEC in this rule check box and then under Validation select the Require DNS clients to check that name and address data has been validated by the DNS server check box.

In the bottom right corner, click Create and then verify that a rule for domain.mil was added under Name Resolution Policy Table.

Click Apply, and then close the Group Policy Management Editor.

Open a Windows PowerShell prompt and enter the following commands:
gpupdate /force <enter>
get-dnsclientnrptpolicy <enter>
In the results, select the True for "DnsSecValidationRequired" setting for the domain.mil namespace.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16812r572260_chk'
  tag severity: 'medium'
  tag gid: 'V-215618'
  tag rid: 'SV-215618r561297_rule'
  tag stig_id: 'WDNS-SC-000010'
  tag gtitle: 'SRG-APP-000215-DNS-000003'
  tag fix_id: 'F-16810r572261_fix'
  tag 'documentable'
  tag legacy: ['SV-73099', 'V-58669']
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
