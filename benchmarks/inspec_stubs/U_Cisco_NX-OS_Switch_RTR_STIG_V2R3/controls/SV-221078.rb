control 'SV-221078' do
  title 'The Cisco switch must not be configured to have any feature enabled that calls home to the vendor.'
  desc 'Call home services will routinely send data such as configuration and diagnostic information to the vendor for routine or emergency analysis and troubleshooting. There is a risk that transmission of sensitive data sent to unauthorized persons could result in data loss or downtime due to an attack.'
  desc 'check', 'Review the switch configuration to determine if the call home service is enabled as shown in the example below:

callhome
 contract-id CompanyXYZ
 customer-id CompanyXYZ
 email-contact netadmin@CompanyXYZ.com
 phone-contact +1-800-555-4567
 enable

If the call home feature is configured to call home to the vendor, this is a finding.'
  desc 'fix', 'Disable the call home feature as shown below:

SW1(config)# callhome
SW1(config-callhome)# no enable 
SW1(config-callhome)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22793r409723_chk'
  tag severity: 'medium'
  tag gid: 'V-221078'
  tag rid: 'SV-221078r856655_rule'
  tag stig_id: 'CISC-RT-000080'
  tag gtitle: 'SRG-NET-000131-RTR-000083'
  tag fix_id: 'F-22782r409724_fix'
  tag 'documentable'
  tag legacy: ['SV-110975', 'V-101871']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
