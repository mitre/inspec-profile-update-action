control 'SV-85997' do
  title 'The CA API Gateway must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

The CA API Gateway uses random numbers for session IDs. Random number generation, out of the box, uses the FIPS 140-2 validated RSA BSAFE Crypto-J Software Module for random number generation for all cryptographic algorithms. By default, JsafeJCE FIPS 186 PRNG algorithm is used in all crypto operations. This can be overridden as per organizational requirements when configured to use a SafeNet Luna HSM, whereupon all cryptographic algorithms performed within the HSM will use its FIPS 140-2 validated random number generation.'
  desc 'check', 'Verify the CA API Gateway is configured to use a SafeNet Luna HSM, whereupon all cryptographic algorithms performed within the HSM will use its FIPS 140-2 validated random number generation. 

If the CA API Gateway is not configured to use the SafeNet Luna HSM, this is a finding.'
  desc 'fix', 'Refer to the “CA API Management Documentation Wiki" at the link below for directions on installing and configuring the CA API Gateway to use a SafeNet Luna HSM. 

https://docops.ca.com/ca-api-gateway/9-0/en/install-and-configure-the-gateway/configure-the-appliance-gateway/configure-hardware-security-modules-hsm/configure-the-safenet-luna-sa-hsm'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71373'
  tag rid: 'SV-85997r1_rule'
  tag stig_id: 'CAGW-GW-000420'
  tag gtitle: 'SRG-NET-000234-ALG-000116'
  tag fix_id: 'F-77687r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
