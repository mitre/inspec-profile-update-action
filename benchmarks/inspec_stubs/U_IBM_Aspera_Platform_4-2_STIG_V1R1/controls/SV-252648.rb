control 'SV-252648' do
  title 'The IBM Aspera High-Speed Transfer Server private/secret cryptographic keys file must have a mode of 0600 or less permissive to prevent unauthorized read access.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder. 

The rootkeystore.db functions as a backup and main source of truth for encrypted secrets."
  desc 'check', 'Verify the rootkeystore.db file has a mode of "0600" or less permissive with the following command:

$ sudo stat -c "%a %n" /opt/aspera/etc/rootkeystore.db

600 /opt/aspera/etc/rootkeystore.db

If the resulting mode is more permissive than "0600", this is a finding.'
  desc 'fix', 'Configure the rootkeystore.db file to have a mode of "0600" or less permissive with the following command:

$ sudo chmod 0600 /opt/aspera/etc/rootkeystore.db'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56104r818112_chk'
  tag severity: 'medium'
  tag gid: 'V-252648'
  tag rid: 'SV-252648r818114_rule'
  tag stig_id: 'ASP4-TS-020320'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56054r818113_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
