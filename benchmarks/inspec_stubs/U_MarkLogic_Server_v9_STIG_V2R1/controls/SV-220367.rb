control 'SV-220367' do
  title 'MarkLogic Server must enforce authorized access to all PKI private keys stored/utilized by the DBMS.'
  desc "The DoD standard for authentication is DoD-approved PKI certificates. PKI certificate-based authentication is performed by requiring the certificate holder to cryptographically prove possession of the corresponding private key.

If the private key is stolen, an attacker can use the private key(s) to impersonate the certificate holder. In cases where the DBMS-stored private keys are used to authenticate the DBMS to the system’s clients, loss of the corresponding private keys would allow an attacker to successfully perform undetected man-in-the-middle attacks against the DBMS system and its clients.

Both the holder of a digital certificate and the issuing authority must take careful measures to protect the corresponding private key. Private keys should always be generated and protected in FIPS 140-2 or 140-3 validated cryptographic modules.

All access to the private key(s) of the DBMS must be restricted to authorized and authenticated users. If unauthorized users have access to one or more of the DBMS's private keys, an attacker could gain access to the key(s) and use them to impersonate the database on the network or otherwise perform unauthorized actions."
  desc 'check', 'Review MarkLogic configuration to determine whether SSL FIPS has been enabled.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon on the left tree menu.
2. Select the local cluster. Click the Configure tab and verify "ssl fips enabled" is set to true. If not, this is a finding.'
  desc 'fix', 'Ensure SSL FIPS has been enabled in MarkLogic server.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon on the left tree menu.
2. Select the local cluster. Click the Configure tab.
3. Set the "ssl fips enabled" setting to true and click "ok".'
  impact 0.7
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22082r401552_chk'
  tag severity: 'high'
  tag gid: 'V-220367'
  tag rid: 'SV-220367r863304_rule'
  tag stig_id: 'ML09-00-004000'
  tag gtitle: 'SRG-APP-000176-DB-000068'
  tag fix_id: 'F-22071r401553_fix'
  tag 'documentable'
  tag legacy: ['SV-110083', 'V-100979']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
