control 'SV-84489' do
  title 'The Exchange Sender filter must block unaccepted domains.'
  desc 'Spam origination sites and other sources of suspected email-borne malware have the ability to corrupt, compromise, or otherwise limit availability of email servers. Limiting exposure to unfiltered inbound messages can reduce the risk of spam and malware impacts. 

The Global Deny list blocks messages originating from specific sources. Most blacklist filtering is done using a commercial Block List service, because eliminating threats from known spammers prevents the messages being evaluated inside the enclave where there is more risk they can do harm. 

Additional sources should also be blocked to supplement the contents of the commercial Block List service. For example, during a zero-day threat action, entries can be added and then removed when the threat is mitigated. An additional best practice is to enter the enterprise’s home domains in the Deny List, because inbound email with a "from" address of the home domain is very likely to be spoofed spam.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the unaccepted domains that are to be blocked.  

Open the Exchange Management Shell and enter the following command:

Get-SenderFilterConfig | Select Name, BlockedDomains, BlockedDomainsAndSubdomains

If the value for BlockedDomains or BlockedDomainsAndSubdomains does not reflect the list of accepted domains, this is a finding.'
  desc 'fix', 'Update the EDSP.

Open the Exchange Management Shell and enter the following command:

For BlockedDomains:

Set-SenderFilterConfig -BlockedDomains <BlockedDomain>

Repeat the procedure for each domain that is to be blocked.

or

For BlockedDomainsAndSubdomains:

Set-SenderFilterConfig -BlockedDomainsAndSubdomains <BlockedDomainAndSubdomain>

Repeat the procedure for each domain and all of its subdomains that are to be blocked.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70335r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69867'
  tag rid: 'SV-84489r1_rule'
  tag stig_id: 'EX13-EG-000180'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76097r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
