control 'SV-83283' do
  title 'The Windows 2008 DNS Servers zone database files must not be accessible for edit/write by users and/or processes other than the Windows 2008 DNS Server service account and/or the DNS database administrator.'
  desc 'Discretionary Access Control (DAC) is based on the premise that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. In a DNS implementation, DAC should be granted to a minimal number of individuals and objects because DNS does not interact directly with users and users do not store and share data with the DNS application directly.

The primary objective of DNS authentication and access control is the integrity of DNS records; only authorized personnel must be able to create and modify resource records, and name servers should only accept updates from authoritative master servers for the relevant zones. Integrity is best assured through authentication and access control features within the name server software and the file system the name server resides on. In order to protect the zone files and configuration data, which should only be accessed by the name service or an administrator, access controls need to be implemented on files, and rights should not be easily propagated to other users. Lack of a stringent access control policy places the DNS infrastructure at risk to malicious persons and attackers, in addition to potential denial of service to network resources.

DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions. DAC models have the potential for the access controls to propagate without limit, resulting in unauthorized access to said objects.

When applications provide a DAC mechanism, the DNS implementation must be able to limit the propagation of those access rights.'
  desc 'check', 'For an Active Directory-integrated DNS implementation, this is Not Applicable by virtue of being compliant with the Windows 2008/2012 AD STIG, since DNS data within an AD-integrated zone is kept within the Active Directory.

For a file-based Windows DNS implementation, log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select each zone.

Right-click each zone and select “Properties”.

Select the “Security” tab.

Review the permissions applied to the zone. No group or user should have greater than READ privileges other than the DNS Admins and the System service account under which the DNS Server Service is running.

If any other account/group has greater than READ privileges, this is a finding.'
  desc 'fix', 'For a file-back Windows DNS implementation, log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select each zone.

Right-click each zone and select “Properties”.

Select the “Security” tab.

Downgrade to READ privileges assigned to any group or user which has greater than READ privileges.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59483r3_chk'
  tag severity: 'medium'
  tag gid: 'V-58611'
  tag rid: 'SV-83283r1_rule'
  tag stig_id: 'WDNS-CM-000020'
  tag gtitle: 'SRG-APP-000516-DNS-000099'
  tag fix_id: 'F-63995r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
