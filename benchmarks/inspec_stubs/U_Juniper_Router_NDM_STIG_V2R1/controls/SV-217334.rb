control 'SV-217334' do
  title 'The Juniper router must be configured to synchronize its clock with the primary and secondary time sources using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the configuration example below.

system {
…
…
…
    }
    ntp {
        server x.x.x.x prefer;
        server x.x.x.x; 
     }

If the router is not configured to synchronize its clock with redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Configure the router to synchronize its clock with redundant authoritative time sources as shown in the example below.

[edit system ntp]
set server x.x.x.x   
set server x.x.x.x prefer'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18561r296580_chk'
  tag severity: 'medium'
  tag gid: 'V-217334'
  tag rid: 'SV-217334r399925_rule'
  tag stig_id: 'JUNI-ND-001020'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-18559r296581_fix'
  tag 'documentable'
  tag legacy: ['SV-101257', 'V-91157']
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
