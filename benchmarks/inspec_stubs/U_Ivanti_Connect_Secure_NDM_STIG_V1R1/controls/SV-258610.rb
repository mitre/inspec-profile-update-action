control 'SV-258610' do
  title 'The ICS must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DOD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DOD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'In the ICS Web UI, navigate to System >> Status >> Overview.

Under "Appliance Details", and "System Date and Time", click "Edit".

If the Time Source is not set to at least two NTP time sources, this is a finding.

If the Time Sources are not specific to a DOD authoritative time source, this is a finding.

If the Time Sources are not configured to use a SHA1 preshared key for authentication, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Status >> Overview.
1. Under "Appliance Details", and "System Date and Time", click "Edit".
2. Click "Use Pool of NTP Servers".
3. Set the IP address or hostname of the first time source.
4. In the "Key 1" box, type the number, algorithm, and key value using this format: 1 SHA1 testingkey
5. Set the IP address or hostname of the second time source, noting that this must be a time source different from the first.
6. In the "Key 2" box, type the number, algorithm, and key value using this format: 1 SHA1 testingkey.
7. Click "Save Changes".
8. Navigate to System >> Log/Monitoring >> Events >> Log on the Web UI.
9. Look in the logs for successful or unsuccessful time sync messages.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62350r930516_chk'
  tag severity: 'medium'
  tag gid: 'V-258610'
  tag rid: 'SV-258610r930518_rule'
  tag stig_id: 'IVCS-NM-000360'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-62259r930517_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
