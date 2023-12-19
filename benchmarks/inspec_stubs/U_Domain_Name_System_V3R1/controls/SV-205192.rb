control 'SV-205192' do
  title 'The DNS server implementation must, when a component failure is detected, activate a notification to the system administrator.'
  desc 'Predictable failure prevention requires organizational planning to address system failure issues. If components key to maintaining systems security fail to function, the system could continue operating in an insecure state. The organization must be prepared and the application must support requirements that specify if the application must alarm for such conditions and/or automatically shut down the application or the system. 

This can include conducting a graceful application shutdown to avoid losing information. Automatic or manual transfer of components from standby to active mode can occur, for example, upon detection of component failures.

If a component such as the DNSSEC or TSIG/SIG(0) signing capabilities were to fail, the DNS server should shut itself down to prevent continued execution without the necessary security components in place. Transactions such as zone transfers would not be able to work correctly anyway in this state.'
  desc 'check', 'Review the DNS server implementation configuration to determine if the DNS server activates a notification to the system administrator when a component failure is detected. 

If the DNS server does not activate a notification to the system administrator when a failure is detected, this is a finding.'
  desc 'fix', 'Configure the DNS server so that when a component failure is detected, the server activates a notification to the system administrator.'
  impact 0.5
  ref 'DPMS Target DNS'
  tag check_id: 'C-5459r392489_chk'
  tag severity: 'medium'
  tag gid: 'V-205192'
  tag rid: 'SV-205192r879657_rule'
  tag stig_id: 'SRG-APP-000268-DNS-000039'
  tag gtitle: 'SRG-APP-000268'
  tag fix_id: 'F-5459r392490_fix'
  tag 'documentable'
  tag legacy: ['SV-69215', 'V-54969']
  tag cci: ['CCI-001328', 'CCI-000366']
  tag nist: ['SI-13 (4) (b)', 'CM-6 b']
end
