control 'SV-252610' do
  title 'The IBM Aspera Shares private/secret cryptographic keys file must be group-owned by nobody to prevent unauthorized read access.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder."
  desc 'check', 'If the IBM Aspera Shares feature of the Aspera Platform is not installed, this is Not Applicable.

Verify the /opt/aspera/shares/u/shares/config/aspera/secret.rb file is group-owned by nobody with the following command:

$ sudo stat -c "%G" /opt/aspera/shares/u/shares/config/aspera/secret.rb

nobody

If "nobody" is not returned as a result, this is a finding.'
  desc 'fix', 'Configure the /opt/aspera/shares/u/shares/config/aspera/secret.rb file to be group-owned by nobody with the following command:

$ sudo chgrp nobody /opt/aspera/shares/u/shares/config/aspera/secret.rb'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56066r817998_chk'
  tag severity: 'medium'
  tag gid: 'V-252610'
  tag rid: 'SV-252610r831515_rule'
  tag stig_id: 'ASP4-SH-060230'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56016r817999_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
