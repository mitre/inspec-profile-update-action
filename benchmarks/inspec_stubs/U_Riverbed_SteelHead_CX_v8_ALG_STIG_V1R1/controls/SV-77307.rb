control 'SV-77307' do
  title 'If TLS optimization is used, the Riverbed Optimization System (RiOS) providing intermediary services for TLS communications traffic must use encryption services that implement NIST FIPS-validated cryptography to protect the confidentiality of TLS.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Encryption provides a means to secure the remote connection so as to prevent unauthorized access to the data traversing the remote access connection, thereby providing a degree of confidentiality. The encryption strength of the mechanism is selected based on the security categorization of the information.

This requirement applies to ALGs providing remote access proxy services as part of its intermediary services (e.g., OWA or TLS gateway).'
  desc 'check', 'Verify that the Riverbed Optimization System (RiOS) is configured to support TLS version 1.1 as a minimum and preferably TLS version 1.2.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> Advanced.
Verify that "Peer Ciphers:" "Rank 1" contains the following string: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

Verify that "Client Ciphers:" "Rank 1" contains the following string: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

Verify that "Server Ciphers:" "Rank 1" contains the following string: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

If any of the above Ciphers contains strings or groups other than what is listed, this is a finding.'
  desc 'fix', 'Configure the Riverbed Optimization System (RiOS) to support TLS version 1.1 as a minimum and preferably TLS version 1.2.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> Advanced Settings
Select "Add a New Peer Cipher".
Scroll down options list until the following is reached: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

Select that string and a "Rank" of "2".
Click "Add".
Select "Rank 1" "Default" Cipher String.
Click "Remove Selected".
Select "Add a New Client Cipher".
Scroll down options list until the following is reached: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

Select that string and a "Rank" of "2".
Click "Add".
Select "Rank 1" "Default" Cipher String.
Click "Remove Selected".
Select "Add a New Server Cipher".
Scroll down options list until the following is reached: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

Select that string and a "Rank" of "2".
Click "Add".
Select "Rank 1" "Default" Cipher String.
Click "Remove Selected".

Navigate to the top of the web page and click "Save" to save these settings permanently.'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 ALG'
  tag check_id: 'C-63611r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62817'
  tag rid: 'SV-77307r1_rule'
  tag stig_id: 'RICX-AG-000039'
  tag gtitle: 'SRG-NET-000062-ALG-000011'
  tag fix_id: 'F-68735r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
