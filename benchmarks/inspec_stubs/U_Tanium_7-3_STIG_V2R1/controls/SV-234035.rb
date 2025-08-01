control 'SV-234035' do
  title 'The Tanium endpoint must have the Tanium Servers public key in its installation.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

'
  desc 'check', %q(The Tanium endpoint makes a connection to the Tanium Server; the endpoint's copy of the Tanium Server's public key is used to verify the validity of the registration day coming from the Tanium Server.

If any endpoint systems do not have the correct Tanium Server public key in its configuration, they will not perform any instructions from the Tanium Server and a record of those endpoints will be listed in the Tanium Server's System Status.

To validate, Click on the navigation button (hamburger menu) on the top left of the console. 

Click on "Administration".

Select the "System Status" tab.

Change "Show systems that have reported in the last:", enter "7" in the first field. 

Select "Days" from the drop down menu in the second field to determine if any endpoints connected with an invalid key.

If any systems are listed with "No" in the "Valid Key" column, this is a finding.)
  desc 'fix', 'For systems which do not have a valid key for the Tanium Server, redeploy the client software from Tanium using the Tanium Client Deployment Tool or work with the Tanium System Administrator to accomplish this.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37220r610605_chk'
  tag severity: 'medium'
  tag gid: 'V-234035'
  tag rid: 'SV-234035r612749_rule'
  tag stig_id: 'TANS-CL-000001'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-37185r610606_fix'
  tag satisfies: ['SRG-APP-000015', 'SRG-APP-000158', 'SRG-APP-000394']
  tag 'documentable'
  tag legacy: ['SV-102143', 'V-92041']
  tag cci: ['CCI-000778', 'CCI-001453', 'CCI-001958']
  tag nist: ['IA-3', 'AC-17 (2)', 'IA-3']
end
