control 'SV-217004' do
  title 'The Cisco router must not be configured to have any feature enabled that calls home to the vendor.'
  desc 'Call home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc 'check', 'Review the router configuration to determine if the call home feature is enabled as shown in the example below.

call-home
 contract-id Company1234
 customer-id Customer1234
 phone-number +1-800-555-4567
 contact-email-addr username@example.com

If the call home feature is configured to call home to the vendor, this is a finding.'
  desc 'fix', 'Disable the call home feature as shown below.

RP/0/0/CPU0:R3(config)#no call-home'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18234r538984_chk'
  tag severity: 'medium'
  tag gid: 'V-217004'
  tag rid: 'SV-217004r538985_rule'
  tag stig_id: 'CISC-RT-000080'
  tag gtitle: 'SRG-NET-000131-RTR-000083'
  tag fix_id: 'F-18232r288853_fix'
  tag 'documentable'
  tag legacy: ['V-96691', 'SV-105829']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
