control 'SV-219316' do
  title 'The Ubuntu operating system must map the authenticated identity to the user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', %q(Verify the Ubuntu operating system has the 'libpam-pkcs11’ package installed, by running the following command:

# dpkg -l | grep libpam-pkcs11

If "libpam-pkcs11" is not installed, this is a finding.

Check if use_mappers is set to pwent in /etc/pam_pkcs11/pam_pkcs11.conf file
# grep use_mappers /etc/pam_pkcs11/pam_pkcs11.conf
use_mappers = pwent

If ‘use_mappers’ is not found or is not set to pwent this is a finding.)
  desc 'fix', 'Install libpam-pkcs11 package on the system. 

Set use_mappers=pwent in /etc/pam_pkcs11/pam_pkcs11.conf

If the system is missing an "/etc/pam_pkcs11/" directory and an "/etc/pam_pkcs11/pam_pkcs11.conf", find an example to copy into place and modify accordingly at "/usr/share/doc/libpam-pkcs11/examples/pam_pkcs11.conf.example.gz".'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21041r305276_chk'
  tag severity: 'high'
  tag gid: 'V-219316'
  tag rid: 'SV-219316r610963_rule'
  tag stig_id: 'UBTU-18-010426'
  tag gtitle: 'SRG-OS-000068-GPOS-00036'
  tag fix_id: 'F-21040r305277_fix'
  tag 'documentable'
  tag legacy: ['SV-109959', 'V-100855']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
