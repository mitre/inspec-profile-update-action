control 'SV-224170' do
  title 'The EDB Postgres Advanced Server must enforce authorized access to all PKI private keys stored/utilized by the EDB Postgres Advanced Server.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where the DBMS-stored private keys are used to authenticate the DBMS to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against the DBMS system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.

All access to the private key(s) of the DBMS must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the DBMS's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', 'Verify User ownership, Group ownership, and permissions on the "server.key" file:

Right-click and select "Properties" on <postgresql data directory>\\server.key

If any users other than the database administrator user (enterprisedb by default) or other users documented in the program security guide have any permissions on this file, this is a finding.'
  desc 'fix', 'Right-click and select "Properties" on <postgresql data directory>\\server.key

Give the database administrator (default "enterprisedb") full control of the file.'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25843r495528_chk'
  tag severity: 'high'
  tag gid: 'V-224170'
  tag rid: 'SV-224170r508023_rule'
  tag stig_id: 'EP11-00-004600'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-25831r495529_fix'
  tag 'documentable'
  tag legacy: ['SV-109471', 'V-100367']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
