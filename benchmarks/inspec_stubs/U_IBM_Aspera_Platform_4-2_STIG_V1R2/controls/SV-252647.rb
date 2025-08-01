control 'SV-252647' do
  title 'The IBM Aspera High-Speed Transfer Server private/secret cryptographic keys file must be owned by root to prevent unauthorized read access.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder. 

The rootkeystore.db functions as a backup and main source of truth for encrypted secrets."
  desc 'check', 'Verify the rootkeystore.db file is owned by root with the following command:

$ sudo stat -c "%U" /opt/aspera/etc/rootkeystore.db

root

If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Configure the rootkeystore.db file to be owned by root with the following command:

$ sudo chown root /opt/aspera/etc/rootkeystore.db'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56103r818109_chk'
  tag severity: 'medium'
  tag gid: 'V-252647'
  tag rid: 'SV-252647r831533_rule'
  tag stig_id: 'ASP4-TS-020310'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56053r818110_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
