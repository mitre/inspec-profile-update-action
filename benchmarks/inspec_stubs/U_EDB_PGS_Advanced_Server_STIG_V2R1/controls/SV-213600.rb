control 'SV-213600' do
  title 'The EDB Postgres Advanced Server must enforce authorized access to all PKI private keys stored/utilized by the EDB Postgres Advanced Server.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where the DBMS-stored private keys are used to authenticate the DBMS to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man in the middle attacks against the DBMS system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 validated cryptographic modules.

All access to the private key(s) of the DBMS must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the DBMS's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', 'Verify User ownership, Group ownership, and permissions on the “server.key” file:
> ls –alL <postgresql data directory>/server.key
If the User owner is not “enterprisedb”, this is a finding
If the Group owner is not “enterprisedb”, this is a finding.
If the file is more permissive than 600, this is a finding.

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  desc 'fix', 'Run these commands:

1) "chown enterprisedb <postgresql data directory>/server.key"

2) "chgrp enterprisedb <postgresql data directory>/server.key"

3) "chmod 600 <postgresql data directory>/server.key"

(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14822r290112_chk'
  tag severity: 'high'
  tag gid: 'V-213600'
  tag rid: 'SV-213600r508024_rule'
  tag stig_id: 'PPS9-00-004600'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-14820r290113_fix'
  tag 'documentable'
  tag legacy: ['SV-83557', 'V-68953']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
