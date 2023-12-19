control 'SV-237050' do
  title 'The A10 Networks ADC must implement load balancing to limit the effects of known and unknown types of Denial of Service (DoS) attacks.'
  desc 'Although maintaining high availability is normally an operational consideration, load balancing is also a useful strategy in mitigating network-based DoS attacks. If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Load balancing provides service redundancy which reduces the susceptibility of the enclave to many DoS attacks. Since one of the primary purposes of the Application Delivery Controller is to balance loads across multiple servers, it would be extremely unusual for it to not be configured to perform this function.'
  desc 'check', 'Review the device configuration.

Ask the Administrator which Application Delivery Services are being provided by the device.

The following command displays information for Server Load Balancing:
show slb

If no Server Load Balancing sessions exist, this is a finding.'
  desc 'fix', 'Configure the device to balance the traffic load of provided services. This will require configuring Server Load Balancing.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC ALG'
  tag check_id: 'C-40269r639595_chk'
  tag severity: 'medium'
  tag gid: 'V-237050'
  tag rid: 'SV-237050r639597_rule'
  tag stig_id: 'AADC-AG-000100'
  tag gtitle: 'SRG-NET-000362-ALG-000120'
  tag fix_id: 'F-40232r639596_fix'
  tag 'documentable'
  tag legacy: ['SV-82487', 'V-67997']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
