control 'SV-254909' do
  title 'The Tanium endpoint must have the Tanium Servers public key in its installation.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.'
  desc 'check', %q(The Tanium endpoint makes a connection to the Tanium Server; the endpoint's copy of the Tanium Server's public key is used to verify the validity of the registration day coming from the Tanium Server.

If any endpoint systems do not have the correct Tanium Server public key in its configuration, they will not perform any instructions from the Tanium Server and a record of those endpoints will be listed in the Tanium Server's System Status.

To validate: 

1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication.

2. Click "Administration" on the top navigation banner.

3 . Select the "Client Status" tab.

4. Click "Administration".

5. Change "Show systems that have reported in the last:", enter "7" in the first field. 

6. Select "Days" from the drop-down menu in the second field to determine if any endpoints connected with an invalid key.

If any systems are listed with "No" in the "Valid Key" column, this is a finding.)
  desc 'fix', 'For systems which do not have a valid key for the Tanium Server, redeploy the client software using the Tanium Client Management (TCM) or work with the Tanium System Administrator to accomplish this.

Documentation on TCM: https://docs.tanium.com/client/client/index.html.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58522r867625_chk'
  tag severity: 'medium'
  tag gid: 'V-254909'
  tag rid: 'SV-254909r867627_rule'
  tag stig_id: 'TANS-AP-000415'
  tag gtitle: 'SRG-APP-000158'
  tag fix_id: 'F-58466r867626_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
