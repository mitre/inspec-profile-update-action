control 'SV-216978' do
  title 'The router must not be configured to have any feature enabled that calls home to the vendor.'
  desc 'Call home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc 'check', 'Verify the call home service is disabled on the device.

If a call home service is enabled, this is a finding.'
  desc 'fix', 'Configure the network device to disable the call home service or feature.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-18208r382640_chk'
  tag severity: 'medium'
  tag gid: 'V-216978'
  tag rid: 'SV-216978r604135_rule'
  tag stig_id: 'SRG-NET-000131-RTR-000083'
  tag gtitle: 'SRG-NET-000131'
  tag fix_id: 'F-18206r382641_fix'
  tag 'documentable'
  tag legacy: ['V-78211', 'SV-92917']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
