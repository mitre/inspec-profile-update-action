control 'SV-251335' do
  title 'An Intrusion Detection and Prevention System (IDPS) sensor must be deployed to monitor all Demilitarized Zone (DMZ) segments housing public servers.'
  desc 'The initial step in IDPS deployment is determining where sensors should be placed. Because attacks originate at the enclave perimeter and within the enclave boundary an IDPS implementation at the enclave perimeter only will not suffice. By placing IDPS technology throughout the Enterprise Regional enclaves and stand-alone enclaves, system administrators can track the spread of attacks and take corrective actions to prevent attacks reaching critical resources.'
  desc 'check', 'Review the DMZ topology and verify public servers are being monitored by an IDPS.

If an IDPS sensor is not deployed to monitor all DMZ segments housing public servers, this is a finding.'
  desc 'fix', 'Place an IDPS sensor in the enclave to monitor public servers.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54770r805958_chk'
  tag severity: 'medium'
  tag gid: 'V-251335'
  tag rid: 'SV-251335r805960_rule'
  tag stig_id: 'NET-IDPS-016'
  tag gtitle: 'NET-IDPS-016'
  tag fix_id: 'F-54723r805959_fix'
  tag 'documentable'
  tag legacy: ['V-18490', 'SV-20025']
  tag cci: ['CCI-001097', 'CCI-001255', 'CCI-002668']
  tag nist: ['SC-7 a', 'SI-4 c 1', 'SI-4 (11)']
end
