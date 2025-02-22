control 'SV-252594' do
  title 'The IBM Aspera Faspex private/secret cryptographic keys file must be owned by faspex to prevent unauthorized read access.'
  desc "Private key data is used to prove that the entity presenting a public key certificate is the certificate's rightful owner. Compromise of private key data allows an adversary to impersonate the key holder."
  desc 'check', 'If the IBM Aspera Faspex feature of the Aspera Platform is not installed, this is Not Applicable.

Verify the /opt/aspera/faspex/config/secret.yml file is owned by faspex with the following command:

$ sudo stat -c "%U" /opt/aspera/faspex/config/secret.yml

faspex

If "faspex" is not returned as a result, this is a finding.'
  desc 'fix', 'Configure the /opt/aspera/faspex/config/secret.yml file to be owned by faspex with the following command:

$ sudo chown faspex /opt/aspera/faspex/config/secret.yml'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56050r817950_chk'
  tag severity: 'medium'
  tag gid: 'V-252594'
  tag rid: 'SV-252594r831508_rule'
  tag stig_id: 'ASP4-FA-050300'
  tag gtitle: 'SRG-NET-000512-ALG-000062'
  tag fix_id: 'F-56000r817951_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
