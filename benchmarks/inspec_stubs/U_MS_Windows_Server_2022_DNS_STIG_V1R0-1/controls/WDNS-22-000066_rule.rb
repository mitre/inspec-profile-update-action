control 'WDNS-22-000066_rule' do
  title 'The Windows 2022 DNS Server must not contain zone records that have been validated annually.'
  desc 'If zone information has not been validated in more than a year, there is no assurance that it is still valid. If invalid records are in a zone, an adversary could potentially use their existence for improper purposes. A standard operating procedure detailing this process can resolve this requirement.'
  desc 'check', %q(This requirement is not applicable for a Windows DNS Server that is hosting only Active Directory (AD)-integrated zones.

For a Windows DNS Server that hosts a mix of AD-integrated zones and manually maintained zones, ask the DNS database administrator if they maintain a separate database with record documentation for the non-AD-integrated zone information. Verify that the record's last verified date is less than one year prior to the date of the review.

If a separate database with record documentation is not maintained for the non-AD-integrated zone information, this is a finding.

If a separate database with record documentation is maintained for the non-AD-integrated zone information, log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Review the zone records of the non-AD-integrated zones and compare to the separate documentation maintained.

Determine if any records have not been validated in more than a year.

If zone records exist that have not been validated in more than a year, this is a finding.)
  desc 'fix', 'Create a separate database to maintain record documentation for non-AD-integrated zones.

Develop a procedure to validate annually all zone information on the DNS server against the separately maintained database.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server and then expand "Forward Lookup Zones".

From the expanded list, click to select the zone.

Select the zone records that have not been validated in more than a year and revalidate.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000066_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000066'
  tag rid: 'WDNS-22-000066_rule'
  tag stig_id: 'WDNS-22-000066'
  tag gtitle: 'SRG-APP-000428-DNS-000061'
  tag fix_id: 'F-WDNS-22-000066_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
