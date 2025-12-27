control 'WDNS-22-000053_rule' do
  title 'The Name Resolution Policy Table (NRPT) must be configured in Group Policy to enforce clients to request DNSSEC validation for a domain.'
  desc 'The NRPT is used to require DNSSEC validation. The NRPT can be configured in local Group Policy for a single computer or domain Group Policy for some or all computers in the domain.'
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

The NRPT is configured in, and deployed to clients from, Group Policy and will be pushed to all clients in the domain. The Active Directory zones will be signed and the clients, with NRPT, will require a validation of signed data when querying.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

At the Windows PowerShell prompt, type the following command:

get-dnsclientnrptpolicy <enter>

In the results, verify the "DnsSecValidationRequired" is "True".

If there are no results to the "get-dnsclientnrptpolicy" cmdlet or the "DnsSecValidationRequired" is not "True", this is a finding.'
  desc 'fix', 'Implement this fix for configuring name resolvers, including DNS servers configured for the caching role only.

On Domain Controller, on the Server Manager menu bar, click "Tools" and then click "Group Policy Management".

In the Group Policy Management console tree, under Domains >> domainname >> Group Policy Objects, right-click "Default Domain Policy" and then click "Edit".

In the Group Policy Management Editor console tree, navigate to Computer Configuration >> Policies >> Windows Settings >> Name Resolution Policy.

In the details pane, under "Create Rules" and "to which part of the namespace does this rule apply", choose "Suffix" from the drop-down list and type "domain.mil" next to "Suffix".
 
On the "DNSSEC" tab, select "Enable DNSSEC" in this rule check box and then under "Validation", select the check box for "Require DNS clients to check that name and address data has been validated by the DNS server".

In the bottom right corner, click "Create" and then verify that a rule for domain.mil was added under the NRPT.

Click "Apply" and then close the Group Policy Management Editor.

Open a Windows PowerShell prompt and enter the following commands:
gpupdate /force <enter>
get-dnsclientnrptpolicy <enter>

In the results, select "True" for the "DnsSecValidationRequired" setting for the domain.mil namespace.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000053_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000053'
  tag rid: 'WDNS-22-000053_rule'
  tag stig_id: 'WDNS-22-000053'
  tag gtitle: 'SRG-APP-000215-DNS-000003'
  tag fix_id: 'F-WDNS-22-000053_fix'
  tag 'documentable'
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
