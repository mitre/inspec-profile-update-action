control 'SV-216996' do
  title 'The Cisco router must not be configured to have any feature enabled that calls home to the vendor.'
  desc 'Call home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc 'check', 'Review the router configuration to determine if the call home service is enabled as shown in the example below:

service call-home
contact-email-addr username@example.com
phone-number "+1-800-555-4567"
customer-id "Customer1234"
contract-id "Company1234"

If the call home feature is configured to call home to the vendor, this is a finding.'
  desc 'fix', 'Disable the call home feature as shown below:

R5(config)#no service call-home'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-18226r855838_chk'
  tag severity: 'medium'
  tag gid: 'V-216996'
  tag rid: 'SV-216996r855840_rule'
  tag stig_id: 'CISC-RT-000080'
  tag gtitle: 'SRG-NET-000131-RTR-000083'
  tag fix_id: 'F-18224r855839_fix'
  tag 'documentable'
  tag legacy: ['SV-106007', 'V-96869']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
