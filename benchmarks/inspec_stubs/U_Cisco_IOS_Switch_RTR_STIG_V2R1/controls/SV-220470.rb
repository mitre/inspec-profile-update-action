control 'SV-220470' do
  title 'The Cisco switch must not be configured to have any feature enabled that calls home to the vendor.'
  desc 'Call home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc 'check', 'Review the switch configuration to determine if the call home service is enabled as shown in the example below: 

call-home 
 contact-email-addr username@example.com 
 phone-number "+1-800-555-4567" 
 customer-id "Customer1234" 
 contract-id "Company1234" 

If the call home feature is configured to call home to the vendor, this is a finding.'
  desc 'fix', 'Disable the call home feature as shown below: 

SW1(config)#no call-home'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22185r508483_chk'
  tag severity: 'medium'
  tag gid: 'V-220470'
  tag rid: 'SV-220470r622190_rule'
  tag stig_id: 'CISC-RT-000080'
  tag gtitle: 'SRG-NET-000131-RTR-000083'
  tag fix_id: 'F-22174r508484_fix'
  tag 'documentable'
  tag legacy: ['SV-110699', 'V-101595']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
