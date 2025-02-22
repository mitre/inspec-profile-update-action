control 'SV-239924' do
  title 'The Cisco ASA must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Review the Cisco ASA configuration to verify it is compliant with this requirement as shown in the configuration example below.

ntp server 10.1.22.2
ntp server 10.1.48.8 prefer

Note: For ASAs running on Firepower Chassis hardware, the NTP settings are visible in the FXOS web UI only (not in the ASA CLI or ASDM web UI).

If the Cisco ASA is not configured to synchronize its clock with redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to synchronize its clock with redundant authoritative time sources as shown in the example below.

ASA(config)# ntp server 10.1.48.8 prefer 
ASA(config)# ntp server 10.1.22.2
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43157r666133_chk'
  tag severity: 'medium'
  tag gid: 'V-239924'
  tag rid: 'SV-239924r877987_rule'
  tag stig_id: 'CASA-ND-000940'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-43116r666134_fix'
  tag 'documentable'
  tag cci: ['CCI-001893']
  tag nist: ['AU-8 (2)']
end
