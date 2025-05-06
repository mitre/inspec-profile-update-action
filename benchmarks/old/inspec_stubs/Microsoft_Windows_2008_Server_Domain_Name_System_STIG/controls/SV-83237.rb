control 'SV-83237' do
  title 'Forwarders on an authoritative Windows 2008 DNS Server, if enabled for external resolution, must only forward to either an internal, non-AD-integrated DNS server or to the DoD Enterprise Recursive Services (ERS).'
  desc "A potential vulnerability of DNS is that an attacker can poison a name server's cache by sending queries that will cause the server to obtain host-to-IP address mappings from bogus name servers that respond with incorrect information. Once a name server has been poisoned, legitimate clients may be directed to non-existent hosts (which constitutes a denial of service), or, worse, hosts that masquerade as legitimate ones to obtain sensitive data or passwords. 

To guard against poisoning, name servers authoritative for .mil domains should be separated functionally from name servers that resolve queries on behalf of internal clients. Organizations may achieve this separation by dedicating machines to each function or, if possible, by running two instances of the name server software on the same machine: one for the authoritative function and the other for the resolving function. In this design, each name server process may be bound to a different IP address or network interface to implement the required segregation."
  desc 'check', 'Note: If the Windows DNS server is in the classified network, this check is Not Applicable.

Note: In Windows DNS Server, if forwarders are configured, the recursion setting must also be enabled since disabling recursion will disable forwarders.

If forwarders are not used, recursion must be disabled. In both cases, the use of root hints must be disabled.

Log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, right-click on the server name for the DNS server and select “Properties”.

Click on the “Forwarders” tab.

If forwarders are not being used, this is not applicable.

Review the IP address(es) for the forwarder(s) use.

If the DNS Server does not forward to another DoD-managed DNS server or to the DoD Enterprise Recursive Services (ERS), this is a finding.

If the "Use root hints if no forwarders are available" is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, right-click on the server name for the DNS server and select “Properties”.

Click on the “Forwarders” tab.

Replace the forwarders being used with another DoD-managed DNS server or the DoD Enterprise Recursive Services (ERS).

Deselect the "Use root hints if no forwarders are available".'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59453r4_chk'
  tag severity: 'medium'
  tag gid: 'V-58581'
  tag rid: 'SV-83237r1_rule'
  tag stig_id: 'WDNS-CM-000004'
  tag gtitle: 'SRG-APP-000383-DNS-000047'
  tag fix_id: 'F-63965r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
