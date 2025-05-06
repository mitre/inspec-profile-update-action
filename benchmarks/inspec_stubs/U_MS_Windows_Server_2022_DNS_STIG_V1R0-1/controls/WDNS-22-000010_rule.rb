control 'WDNS-22-000010_rule' do
  title 'Forwarders on an authoritative Windows 2022 DNS Server, if enabled for external resolution, must forward only to an internal, non-Active Directory (AD)-integrated DNS server or to the DOD Enterprise Recursive Services (ERS).'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to nonexistent hosts (which constitutes a denial of service) or hosts that masquerade as legitimate ones to obtain sensitive data or passwords. 

To guard against poisoning, name servers authoritative for .mil domains should be separated functionally from name servers that resolve queries on behalf of internal clients. Organizations may achieve this separation by dedicating machines to each function or, if possible, by running two instances of the name server software on the same machine: one for the authoritative function and the other for the resolving function. In this design, each name server process may be bound to a different IP address or network interface to implement the required segregation."
  desc 'check', 'Note: If the Windows DNS Server is in the classified network, this check is not applicable. If forwarders are not being used, this is not applicable.

Note: In Windows DNS Server, if forwarders are configured, the recursion setting must also be enabled because disabling recursion will disable forwarders.

If forwarders are not used, recursion must be disabled. In both cases, the use of root hints must be disabled.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, right-click on the server name for the DNS server and select "Properties".

Click the "Forwarders" tab.

Review the IP address(es) for the forwarder(s) use.

If the DNS server does not forward to another DOD-managed DNS server or to the DOD ERS, this is a finding.

If "Use root hints if no forwarders are available" is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, right-click on the server name for the DNS server and select "Properties".

Click the "Forwarders" tab.

Replace the forwarders being used with another DOD-managed DNS server or the DOD ERS.

Deselect "Use root hints if no forwarders are available".'
  impact 0.5
  tag check_id: 'C-WDNS-22-000010_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000010'
  tag rid: 'WDNS-22-000010_rule'
  tag stig_id: 'WDNS-22-000010'
  tag gtitle: 'SRG-APP-000383-DNS-000047'
  tag fix_id: 'F-WDNS-22-000010_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
