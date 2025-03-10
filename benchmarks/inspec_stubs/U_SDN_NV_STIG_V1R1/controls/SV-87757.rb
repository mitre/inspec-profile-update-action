control 'SV-87757' do
  title 'Servers hosting SDN controllers must have an HIDS implemented to detect unauthorized changes.'
  desc 'The SDN controller is the backbone of the SDN infrastructure. If the server hosting the SDN controller is breached or if unauthorized changes are made to the device, the SDN controller may not have the appropriate resources to function properly or may even be disabled. A host intrusion detection system (HIDS) can monitor and report system configuration changes and prevent malicious or anomalous activity.'
  desc 'check', 'Review all servers hosting an SDN controller and verify that an HIDS has been installed and enabled.

If an HIDS has not been installed and enabled on all servers hosting an SDN controller, this is a finding.'
  desc 'fix', 'Install and enable an HIDS on all servers hosting an SDN controller.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73105'
  tag rid: 'SV-87757r1_rule'
  tag stig_id: 'NET-SDN-018'
  tag gtitle: 'NET-SDN-018'
  tag fix_id: 'F-79551r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001255']
  tag nist: ['SI-4 c 1']
end
