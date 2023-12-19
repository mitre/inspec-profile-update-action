control 'SV-243238' do
  title 'The network device must not be configured to have any feature enabled that calls home to the vendor.'
  desc 'Call-home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack. (See SRG-NET-000131-RTR-000083.)'
  desc 'check', 'Review the device configuration to determine if the call home service or feature is disabled on the device. 

If the call home service is enabled on the device, this is a finding.

Note: This feature can be enabled if the communication is only to a server residing in the local area network or enclave.'
  desc 'fix', 'Configure the network device to disable the call home service or feature.

Note: This feature can be enabled if the communication is only to a server residing in the local area network or enclave.'
  impact 0.5
  ref 'DPMS Target Network WLAN Controller Platform'
  tag check_id: 'C-46513r720167_chk'
  tag severity: 'medium'
  tag gid: 'V-243238'
  tag rid: 'SV-243238r720169_rule'
  tag stig_id: 'WLAN-NW-001300'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-46470r720168_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
