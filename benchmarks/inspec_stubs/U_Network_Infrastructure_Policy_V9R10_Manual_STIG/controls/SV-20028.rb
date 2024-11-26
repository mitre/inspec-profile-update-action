control 'SV-20028' do
  title 'An Intrusion Detection and Prevention System (IDPS) sensor must be deployed to monitor network segments that house network security management servers.'
  desc 'The initial step in IDPS deployment is determining where sensors should be placed. Because attacks originate at the enclave perimeter and within the enclave boundary an IDPS implementation at the enclave perimeter only will not suffice. By placing IDPS technology throughout the Enterprise Regional enclaves and stand-alone enclaves, system administrators can track the spread of attacks and take corrective actions to prevent attacks reaching critical resources.'
  desc 'check', 'Review the management network topology and verify network security management servers are being monitored by an IDPS.

If an IDPS sensor is not deployed to monitor all segments housing network security management servers, this is a finding.'
  desc 'fix', 'Install an IDPS to monitor and protect the Management Network (management subnet or OOB network).'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-21127r3_chk'
  tag severity: 'medium'
  tag gid: 'V-18493'
  tag rid: 'SV-20028r2_rule'
  tag stig_id: 'NET-IDPS-019'
  tag gtitle: 'IDPS sensor is not monitoring Network MGT network'
  tag fix_id: 'F-19083r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001097', 'CCI-001255', 'CCI-002668']
  tag nist: ['SC-7 a', 'SI-4 c 1', 'SI-4 (11)']
end
