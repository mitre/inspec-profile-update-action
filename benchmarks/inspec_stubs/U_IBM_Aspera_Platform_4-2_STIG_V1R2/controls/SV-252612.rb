control 'SV-252612' do
  title 'The IBM Aspera Shares private/secret cryptographic keys file must have a mode of 0400 or less permissive to prevent unauthorized read access.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder."
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify the /opt/aspera/shares/u/shares/config/aspera/secret.rb file has a mode of "0400" or less permissive with the following command:

$ sudo stat -c "%a %n" /opt/aspera/shares/u/shares/config/aspera/secret.rb

400 /opt/aspera/shares/u/shares/config/aspera/secret.rb

If the resulting mode is more permissive than "0400", this is a finding.'
  desc 'fix', 'Configure the /opt/aspera/shares/u/shares/config/aspera/secret.rb file to have a mode of "0400" or less permissive with the following command:

$ sudo chmod 0400 /opt/aspera/shares/u/shares/config/aspera/secret.rb'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56068r818004_chk'
  tag severity: 'medium'
  tag gid: 'V-252612'
  tag rid: 'SV-252612r831517_rule'
  tag stig_id: 'ASP4-SH-060250'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56018r818005_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
