control 'SV-252576' do
  title 'The IBM Aspera Faspex private/secret cryptographic keys file must have a mode of 0600 or less permissive to prevent unauthorized read access.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder."
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify the /opt/aspera/faspex/config/secret.yml file has a mode of "0600" or less permissive with the following command:

$ sudo stat -c "%a %n" /opt/aspera/faspex/config/secret.yml

600 /opt/aspera/faspex/config/secret.yml

If the resulting mode is more permissive than "0600", this is a finding.'
  desc 'fix', 'Configure the /opt/aspera/faspex/config/secret.yml file to have a mode of "0600" or less permissive with the following command:

$ sudo chmod 0600 /opt/aspera/faspex/config/secret.yml'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56032r817896_chk'
  tag severity: 'medium'
  tag gid: 'V-252576'
  tag rid: 'SV-252576r831500_rule'
  tag stig_id: 'ASP4-FA-050110'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-55982r817897_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
