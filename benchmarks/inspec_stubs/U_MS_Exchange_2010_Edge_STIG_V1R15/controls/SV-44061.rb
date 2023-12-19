control 'SV-44061' do
  title 'Sender Filter must block accepted domains at the edge.'
  desc "SPAM origination sites and other sources of suspected Email-borne malware have the ability to corrupt, compromise, or otherwise limit availability of Email servers. Limiting exposure to unfiltered inbound messages can reduce the risk of SPAM and malware impacts. 

The Global Deny list block messages originating from specific sources. Most Black List filtering is done using a commercial 'Block List' service, because eliminating threats from known SPAMMERS prevents the messages being evaluated inside the enclave where there is more risk they can do harm. 

Additional sources should also be blocked to supplement the contents of the commercial 'Block List Service'.   For example, during a 0-Day threat action, entries can be added, and then removed when the threat is mitigated. An additional best practice is to enter the enterprise’s home domains in the Deny List, because inbound Email with a ‘from’ address of the home domain is very likely to be SPOOFED SPAM."
  desc 'check', "Access the EDSP for the list of accepted domains for which this server accepts inbound email.  

Open the Exchange Management Shell and enter the following command:

Get-SenderFilterConfig

If the value for 'BlockedDomains' or 'BlockedDomainsAndSubdomains' does not reflect the list of accepted domains, this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderFilterConfig -BlockedDomains <domain list>
Or
Set-SenderFilterConfig -BlockedDomainsAndSubdomains <domain list>

Enter the list of accepted domains for this email system. 
Document the configuration in the EDSP.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33641'
  tag rid: 'SV-44061r1_rule'
  tag stig_id: 'Exch-2-317'
  tag gtitle: 'Exch-2-317'
  tag fix_id: 'F-37534r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
