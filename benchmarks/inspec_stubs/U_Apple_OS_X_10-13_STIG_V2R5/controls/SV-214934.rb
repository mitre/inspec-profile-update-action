control 'SV-214934' do
  title 'The macOS system must enable certificate for smartcards.'
  desc 'To prevent untrusted certificates the certificates on a smartcard card must be valid in these ways: its issuer is system-trusted, the certificate is not expired, its "valid-after" date is in the past, and it passes CRL and OCSP checking.'
  desc 'check', 'To view the setting for the smartcard certification configuration, run the following command:

sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep checkCertificateTrust

If the output is null or not "checkCertificateTrust = 1;" this is a finding.'
  desc 'fix', 'This setting is enforced using the "Smartcard" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16134r397374_chk'
  tag severity: 'medium'
  tag gid: 'V-214934'
  tag rid: 'SV-214934r609363_rule'
  tag stig_id: 'AOSX-13-067035'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-16132r397375_fix'
  tag 'documentable'
  tag legacy: ['SV-96463', 'V-81749']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
