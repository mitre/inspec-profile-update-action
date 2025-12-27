control 'SV-220498' do
  title 'The Cisco switch must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the configuration example below:

ntp distribute
ntp server 10.1.12.10
ntp server 10.1.22.13
ntp commit

If the Cisco switch is not configured to synchronize its clock with redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to synchronize its clock with redundant authoritative time sources as shown in the example below:

SW1(config)# feature ntp
SW1(config)# ntp distribute 
SW1(config)# ntp server 10.1.12.10
SW1(config)# ntp server 10.1.22.13
SW1(config)# ntp commit
SW1(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22213r539215_chk'
  tag severity: 'medium'
  tag gid: 'V-220498'
  tag rid: 'SV-220498r604141_rule'
  tag stig_id: 'CISC-ND-001030'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-22202r539216_fix'
  tag 'documentable'
  tag legacy: ['SV-110645', 'V-101541']
  tag cci: ['CCI-001893', 'CCI-000366']
  tag nist: ['AU-8 (2)', 'CM-6 b']
end
