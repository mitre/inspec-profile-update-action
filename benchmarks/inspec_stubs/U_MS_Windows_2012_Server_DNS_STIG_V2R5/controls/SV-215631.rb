control 'SV-215631' do
  title 'The Windows 2012 DNS Server must not contain zone records that have not been validated in over a year.'
  desc 'If zone information has not been validated in over a year, then there is no assurance that it is still valid.  If invalid records are in a zone, then an adversary could potentially use their existence for improper purposes. An SOP detailing this process can resolve this requirement.'
  desc 'check', "This requirement is not applicable for a Windows DNS Server which is only hosting AD-integrated zones.

For a Windows DNS Server which hosts a mix of AD-integrated zones and manually maintained zones, ask the DNS database administrator if they maintain a separate database with record documentation for the non-AD-integrated zone information. The reviewer should check that the record's last verified date is less than one year prior to the date of the review.

If a separate database with record documentation is not maintained for the non-AD-integrated zone information, this is a finding.

If a separate database with record documentation is maintained for the non-AD-integrated zone information, Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Review the zone records of the non-AD-integrated zones and compare to the separate documentation maintained.

Determine if any records have not been validated in over a year.

If zone records exist which have not been validated in over a year, this is a finding."
  desc 'fix', 'Create a separate database to maintain record documentation for non-AD-integrated zones.

Develop a procedure to validate annually all zone information on the DNS server against the separately maintained database.

Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

On the opened DNS Manager snap-in from the left pane, expand the server name for the DNS server, and then expand Forward Lookup Zones.

From the expanded list, click to select the zone.

Select the zone records which have not been validated in over a year and revalidate.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16825r572273_chk'
  tag severity: 'medium'
  tag gid: 'V-215631'
  tag rid: 'SV-215631r561297_rule'
  tag stig_id: 'WDNS-SC-000025'
  tag gtitle: 'SRG-APP-000428-DNS-000061'
  tag fix_id: 'F-16823r572274_fix'
  tag 'documentable'
  tag legacy: ['SV-73125', 'V-58695']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
