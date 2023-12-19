control 'SV-77311' do
  title 'The Riverbed Optimization System (RiOS) that provides intermediary services for TLS must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks which exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol thus are in scope for this requirement. NIS SP 800-52 provides guidance.

SP 800-52 sets TLS version 1.1 as a minimum version, thus all versions of SSL are not allowed (including for client negotiation) either on DoD-only or on public facing servers.'
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
Navigate to Configure >> Optimization >> Advanced.
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
  tag check_id: 'C-63615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62821'
  tag rid: 'SV-77311r1_rule'
  tag stig_id: 'RICX-AG-000041'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-68739r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
