control 'SV-225213' do
  title 'The macOS system must be configured so that the login command requires smart card authentication.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'For systems that are not utilizing smart card authentication, this is Not Applicable.

To verify that the "login" command has been configured to require smart card authentication, run the following command:

# cat /etc/pam.d/login | grep -i pam_smartcard.so

If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing, this is a finding.'
  desc 'fix', 'Make a backup of the PAM LOGIN settings using the following command:

sudo cp /etc/pam.d/login /etc/pam.d/login_backup_`date "+%Y-%m-%d_%H:%M"`

Replace the contents of "/etc/pam.d/login" with the following:

# login: auth account password session
auth		sufficient	  pam_smartcard.so
auth       optional       pam_krb5.so use_kcminit
auth       optional       pam_ntlm.so try_first_pass
auth       optional       pam_mount.so try_first_pass
auth       required       pam_opendirectory.so try_first_pass
auth       required       pam_deny.so
account    required       pam_nologin.so
account    required       pam_opendirectory.so
password   required       pam_opendirectory.so
session    required       pam_launchd.so
session    required       pam_uwtmp.so
session    optional       pam_mount.so'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26912r467807_chk'
  tag severity: 'medium'
  tag gid: 'V-225213'
  tag rid: 'SV-225213r610901_rule'
  tag stig_id: 'AOSX-15-003050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26900r485776_fix'
  tag 'documentable'
  tag legacy: ['SV-111807', 'V-102845']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
