control 'SV-77323' do
  title 'The Riverbed Optimization System (RiOS) must protect the authenticity of communications sessions by configuring securing pairing trusts for SSL and secure protocols.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

This authenticity protection control focuses on communications protection for the application session rather than for the network packet and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of mutual authentication (two-way/bidirectional).'
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
  tag check_id: 'C-63627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62833'
  tag rid: 'SV-77323r1_rule'
  tag stig_id: 'RICX-AG-000123'
  tag gtitle: 'SRG-NET-000230-ALG-000113'
  tag fix_id: 'F-68751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
