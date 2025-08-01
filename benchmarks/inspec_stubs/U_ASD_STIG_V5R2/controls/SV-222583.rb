control 'SV-222583' do
  title 'The application must use the Federal Information Processing Standard (FIPS) 140-2-validated cryptographic modules and random number generator if the application implements encryption, key exchange, digital signature, and hash functionality.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify if the application implements encryption, key exchange, digital signature, or hash functionality.

Identify the cryptographic modules utilized by the application for these functions. The application may be designed to use the crypto functionality of the underlying OS or it may be a product of the application itself.

Identify the cryptographic service provider utilized by the application and reference the NIST validation website to ensure the algorithms utilized are approved.

http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140val-all.htm

If the application does not use FIPS 140-2-approved encryption algorithms, this is a finding.'
  desc 'fix', 'Configure the application to use FIPS 140-2-validated cryptographic modules when the application implements encryption, key exchange, digital signatures, random number generators, and hash functionality.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24253r493657_chk'
  tag severity: 'medium'
  tag gid: 'V-222583'
  tag rid: 'SV-222583r508029_rule'
  tag stig_id: 'APSC-DV-002290'
  tag gtitle: 'SRG-APP-000224'
  tag fix_id: 'F-24242r493658_fix'
  tag 'documentable'
  tag legacy: ['SV-84839', 'V-70217']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
