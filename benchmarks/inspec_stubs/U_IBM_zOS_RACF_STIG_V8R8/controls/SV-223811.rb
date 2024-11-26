control 'SV-223811' do
  title 'IBM z/OS, for PKI-based authentication, must use the ICSF or ESM for key management.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Any keys or Certificates must be managed in ICSF or the external security manager and not in UNIX files.

From the ISPF Command Shell enter:
OMVS
enter
find / -name *.kdb
and
find / -name *.jks

If any files are present, this is a finding.'
  desc 'fix', 'Define all Keys/Certificates to ICSF or the security database.

Remove all .kdb  and .jks key files.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25484r816950_chk'
  tag severity: 'medium'
  tag gid: 'V-223811'
  tag rid: 'SV-223811r816951_rule'
  tag stig_id: 'RACF-SH-000060'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-25472r811014_fix'
  tag 'documentable'
  tag legacy: ['SV-107433', 'V-98329']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
