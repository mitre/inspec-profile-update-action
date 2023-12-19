control 'SV-209614' do
  title 'The macOS system must enable certificate for smartcards.'
  desc 'To prevent untrusted certificates the certificates on a smartcard card must be valid in these ways: its issuer is system-trusted, the certificate is not expired, its "valid-after" date is in the past, and it passes CRL and OCSP checking.'
  desc 'check', 'To view the setting for the smartcard certification configuration, run the following command:

sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep checkCertificateTrust

If the return is not "checkCertificateTrust = 1;" with the numeral equal to 1 or greater, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Smart Card Policy" configuration profile. 

Note: Before applying the "Smart Card Policy", the supplemental guidance provided with the STIG should be consulted to ensure continued access to the operating system.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9865r282324_chk'
  tag severity: 'medium'
  tag gid: 'V-209614'
  tag rid: 'SV-209614r610285_rule'
  tag stig_id: 'AOSX-14-003002'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-9865r282325_fix'
  tag 'documentable'
  tag legacy: ['SV-105097', 'V-95959']
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
