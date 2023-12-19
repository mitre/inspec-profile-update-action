control 'SV-233224' do
  title 'The application must protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that either are distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, TLS VPNs, or IPsec.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Review container platform configuration to determine if it is using a transmission method that maintains the confidentiality and integrity of information during transmission.

If a transmission method is not being used that maintains the confidentiality and integrity of the data, this is a finding.'
  desc 'fix', 'Configure the container platform to utilize a transmission method that maintains the confidentiality and integrity of information during transmission.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36160r810986_chk'
  tag severity: 'medium'
  tag gid: 'V-233224'
  tag rid: 'SV-233224r810988_rule'
  tag stig_id: 'SRG-APP-000439-CTR-001080'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-36128r810987_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
