control 'SV-252530' do
  title 'The macOS system must be configured so that the sudo command requires smart card authentication.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'For systems that are not utilizing smart card authentication, this is Not Applicable.

To verify that the "sudo" command has been configured to require smart card authentication, run the following command:

cat /etc/pam.d/sudo | grep -i pam_smartcard.so

If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing, this is a finding.'
  desc 'fix', 'Make a backup of the PAM SUDO settings using the following command:

cp /etc/pam.d/login /etc/pam.d/sudo_backup_`date "+%Y-%m-%d_%H:%M"`

Replace the contents of "/etc/pam.d/sudo" with the following:

# sudo: auth account password session
auth    sufficient   pam_smartcard.so
#auth    required    pam_opendirectory.so
auth    required    pam_deny.so
account  required    pam_permit.so
password  required    pam_deny.so
session  required    pam_permit.so'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55986r816402_chk'
  tag severity: 'medium'
  tag gid: 'V-252530'
  tag rid: 'SV-252530r816489_rule'
  tag stig_id: 'APPL-12-003052'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55936r816488_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
