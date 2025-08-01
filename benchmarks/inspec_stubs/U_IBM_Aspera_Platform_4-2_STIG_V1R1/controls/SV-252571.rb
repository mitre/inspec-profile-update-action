control 'SV-252571' do
  title 'The IBM Aspera Console private/secret cryptographic keys file must be group-owned by root to prevent unauthorized read access.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder."
  desc 'check', 'Verify the /opt/aspera/console/config/secret.yml file is group-owned by root with the following command:

$ sudo stat -c "%G" /opt/aspera/console/config/secret.yml

root

If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Configure the /opt/aspera/console/config/secret.yml file to be group-owned by root with the following command:

$ sudo chgrp root /opt/aspera/console/config/secret.yml'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56027r817881_chk'
  tag severity: 'medium'
  tag gid: 'V-252571'
  tag rid: 'SV-252571r817883_rule'
  tag stig_id: 'ASP4-CS-040240'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55977r817882_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
