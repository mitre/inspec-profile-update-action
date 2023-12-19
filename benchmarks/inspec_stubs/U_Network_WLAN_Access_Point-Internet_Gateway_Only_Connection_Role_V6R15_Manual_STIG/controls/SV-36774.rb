control 'SV-36774' do
  title 'A service or feature that calls home to the vendor must be disabled.'
  desc 'Call home services or features will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting.  The risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc 'check', 'Review the device configuration to determine if the call home service or feature is disabled on the device. If the call home service is enabled on the device, this is a finding.

Note: This feature can be enabled if the communication is only to a server residing in the local area network or enclave.'
  desc 'fix', 'Configure the network device to disable the call home service or feature.

Note: This feature can be enabled if the communication is only to a server residing in the local area network or enclave.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-35853r4_chk'
  tag severity: 'medium'
  tag gid: 'V-28784'
  tag rid: 'SV-36774r5_rule'
  tag stig_id: 'NET0405'
  tag gtitle: 'Call home service is disabled.'
  tag fix_id: 'F-31103r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Network Security Officer']
end
