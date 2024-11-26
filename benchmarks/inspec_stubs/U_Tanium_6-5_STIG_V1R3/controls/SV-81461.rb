control 'SV-81461' do
  title 'The Tanium endpoint must have the Tanium Servers public key in its installation.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection. 

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless. 

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', %q(The Tanium endpoint makes a connection to the Tanium Server, the endpoint's copy of the Tanium Server's public key is used to verify the validity of the registration day coming from the Tanium Server.

If any endpoint systems do not have the correct Tanium Server public key in its configuration, they will not perform any instructions from the Tanium Server and a record of those endpoints will be listed in the Tanium Server's System Status.

To validate, Review in console--Administration, System Status, to determine if any endpoints connected with an invalid key.

If any systems are listed with "No" under the column for "Valid Key", this is a finding.)
  desc 'fix', 'For systems which do not have a valid key for the Tanium Server, re-deploy the client software from Tanium.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66971'
  tag rid: 'SV-81461r1_rule'
  tag stig_id: 'TANS-CL-000001'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-73071r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
