control 'SV-206509' do
  title 'The Central Log Server must be configured to protect the confidentiality and integrity of transmitted information.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised since unprotected communications can be intercepted and either read or altered. 

This requirement applies only to those applications that are either distributed or can allow access to data non-locally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, applications need to leverage transmission protection mechanisms, such as TLS, SSL VPNs, or IPSEC.

Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification. Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to use transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec along with integrity protections such as FIPS 140-2 validated digital signature and hash function.

If the Central Log Server is not configured to protect the confidentiality and integrity of transmitted information, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to use transmission protection mechanisms, such as TLS, SSL VPNs, or IPsec along with integrity protections  such as FIPS 140-2 validated digital signature and hash function.'
  impact 0.7
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6769r285768_chk'
  tag severity: 'high'
  tag gid: 'V-206509'
  tag rid: 'SV-206509r855316_rule'
  tag stig_id: 'SRG-APP-000439-AU-004310'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-6769r285769_fix'
  tag 'documentable'
  tag legacy: ['SV-96015', 'V-81301']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
