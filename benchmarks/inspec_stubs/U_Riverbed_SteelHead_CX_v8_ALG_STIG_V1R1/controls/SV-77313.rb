control 'SV-77313' do
  title 'The Riverbed Optimization System (RiOS) providing intermediary services for remote access communications traffic must use NIST FIPS-validated cryptography to protect the integrity of remote access sessions.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

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
  tag check_id: 'C-63617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62823'
  tag rid: 'SV-77313r1_rule'
  tag stig_id: 'RICX-AG-000042'
  tag gtitle: 'SRG-NET-000063-ALG-000012'
  tag fix_id: 'F-68741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
