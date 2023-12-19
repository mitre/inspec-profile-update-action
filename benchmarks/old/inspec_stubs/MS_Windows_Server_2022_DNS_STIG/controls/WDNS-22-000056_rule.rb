control 'WDNS-22-000056_rule' do
  title 'Automatic Update of Trust Anchors must be enabled on key rollover.'
  desc 'A trust anchor is a preconfigured public key associated with a specific zone. A validating DNS server must be configured with one or more trust anchors to perform validation. If the DNS server is running on a domain controller, trust anchors are stored in the forest directory partition in Active Directory Domain Services (AD DS) and can be replicated to all domain controllers in the forest. 

On standalone DNS servers, trust anchors are stored in a file named "TrustAnchors.dns". A DNS server running Windows Server 2022 also displays configured trust anchors in the DNS Manager console tree in the "Trust Points" container. Trust anchors can also be viewed by executing Windows PowerShell commands or "Dnscmd.exe" at a Windows command prompt.'
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that host only Active Directory-integrated zones or for Windows 2022 DNS Servers on a classified network.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

If not automatically started, initialize the Server Manager window by clicking its icon from the bottom left corner of the screen.

Once the Server Manager window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the "SERVERS" section, right-click the DNS server.

From the context menu that appears, click "DNS Manager".

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand "Forward Lookup Zones".

From the expanded list, click to select and then right-click the zone name.

From the displayed context menu, click DNSSEC >> Properties.

Click the "KSK" tab.

For each KSK that is listed under Key signing keys (KSKs), click the KSK, click "Edit", and in the "Key Rollover" section, verify the "Enable automatic rollover" check box is selected.

If the "Enable automatic rollover" check box is not selected for every KSK listed, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

If not automatically started, initialize the Server Manager window by clicking its icon from the bottom left corner of the screen.

Once the Server Manager window is initialized, from the left pane, click to select the DNS category.

From the right pane, under the "SERVERS" section, right-click the DNS server.

From the context menu that appears, click "DNS Manager".

On the opened DNS Manager snap-in from the left pane, expand the server name and then expand "Forward Lookup Zones".

From the expanded list, click to select and then right-click the zone name.

From the displayed context menu, click DNSSEC >> Properties.

Click the "KSK" tab.

For each KSK that is listed under key signing keys (KSKs), click the KSK, click "Edit", and in the "Key Rollover" section, select the "Enable automatic rollover" check box.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000056_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000056'
  tag rid: 'WDNS-22-000056_rule'
  tag stig_id: 'WDNS-22-000056'
  tag gtitle: 'SRG-APP-000215-DNS-000026'
  tag fix_id: 'F-WDNS-22-000056_fix'
  tag 'documentable'
  tag cci: ['CCI-001663']
  tag nist: ['SC-20 b']
end
