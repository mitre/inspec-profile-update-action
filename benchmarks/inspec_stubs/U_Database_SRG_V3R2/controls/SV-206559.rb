control 'SV-206559' do
  title 'The DBMS must enforce authorized access to all PKI private keys stored/utilized by the DBMS.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder.  In cases where the DBMS-stored private keys are used to authenticate the DBMS to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against the DBMS system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.

All access to the private key(s) of the DBMS must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the DBMS's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', "Review DBMS configuration to determine whether appropriate access controls exist to protect the DBMS's private key(s). If the DMBS’s private key(s) are not stored in a FIPS 140-2 validated cryptographic module, this is a finding.

If access to the DBMS’s private key(s) is not restricted to authenticated and authorized users, this is a finding."
  desc 'fix', 'Store all DBMS PKI private keys in a FIPS 140-2 validated cryptographic module.  Ensure access to the DBMS PKI private keys is restricted to only authenticated and authorized users.'
  impact 0.7
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6819r291345_chk'
  tag severity: 'high'
  tag gid: 'V-206559'
  tag rid: 'SV-206559r810838_rule'
  tag stig_id: 'SRG-APP-000176-DB-000068'
  tag gtitle: 'SRG-APP-000176'
  tag fix_id: 'F-6819r291346_fix'
  tag 'documentable'
  tag legacy: ['SV-42813', 'V-32476']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
