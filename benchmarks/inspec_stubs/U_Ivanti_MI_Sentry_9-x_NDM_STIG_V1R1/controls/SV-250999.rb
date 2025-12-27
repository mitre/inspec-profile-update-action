control 'SV-250999' do
  title 'MobileIron Sentry must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Verify the MobileIron Sentry is configured with multiple date and time servers (NTP).

1. Log in to MobileIron Sentry.
2. Go to Settings >> Date and Time (NTP).
3. Verify the NTP servers are configured.

If NTP servers are not configured, this is a finding.

Refer to the "Date and Time (NTP)" section of the "MobileIron Sentry 9.8.0 Guide for MobileIron Core" for more information.'
  desc 'fix', 'Configure the MobileIron Sentry with multiple date and time servers (NTP).

1. Log in to MobileIron Sentry.
2. Go to Settings >> Date and Time (NTP).
3. Under Time Source dropdown, select "NTP".
4. Enter at least Primary and Secondary NTP servers.
5. Click "Apply" and "Save" in the top right corner.

Refer to the "Date and Time (NTP)" section of the "MobileIron Sentry 9.8.0 Guide for MobileIron Core" for more information.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54434r802217_chk'
  tag severity: 'medium'
  tag gid: 'V-250999'
  tag rid: 'SV-250999r802219_rule'
  tag stig_id: 'MOIS-ND-000700'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-54388r802218_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
