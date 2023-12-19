control 'SV-77309' do
  title 'If TLS optimization is used, the Riverbed Optimization System (RiOS) that stores secret or private keys must use FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder.

Private key data associated with software certificates, including those issued to an ALG, is required to be generated and protected in at least a FIPS 140-2 Level 1 validated cryptographic module.

The Riverbed RiOS secure vault contains sensitive information from your SteelHead appliance configuration, including SSL private keys and the data store encryption key. These configuration settings are encrypted on the disk using AES 256-bit encryption.

The secure vault always runs in FIPS mode."
  desc 'check', 'Verify the Riverbed Optimization System (RiOS) is configured to support FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.

Navigate to the device Management Console.
Navigate to Configure >> Optimization >> Advanced.
Verify that "Peer Ciphers:" "Rank 1" contains the following string: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

Verify that "Client Ciphers:" "Rank 1" contains the following string: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

Verify that "Server Ciphers:" "Rank 1" contains the following string: 

"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

If any of the above Ciphers contains strings or groups other than what is listed, this is a finding.'
  desc 'fix', 'Configure the Riverbed Optimization System (RiOS) to support FIPS-approved key management technology and processes in the production and control of private/secret cryptographic keys.

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
  tag check_id: 'C-63613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62819'
  tag rid: 'SV-77309r1_rule'
  tag stig_id: 'RICX-AG-000040'
  tag gtitle: 'SRG-NET-000062-ALG-000092'
  tag fix_id: 'F-68737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
