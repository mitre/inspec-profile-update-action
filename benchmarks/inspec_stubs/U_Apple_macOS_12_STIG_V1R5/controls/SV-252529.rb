control 'SV-252529' do
  title 'The macOS system must be configured so that the su command requires smart card authentication.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'For systems that are not utilizing smart card authentication, this is Not Applicable.

To verify that the "su" command has been configured to require smart card authentication, run the following command:

cat /etc/pam.d/su | grep -i pam_smartcard.so

If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing, this is a finding.'
  desc 'fix', 'Make a backup of the PAM SU settings using the following command:
cp /etc/pam.d/su /etc/pam.d/su_backup_`date "+%Y-%m-%d_%H:%M"`

Replace the contents of "/etc/pam.d/su" with the following:

# su: auth account password session
auth    sufficient  pam_smartcard.so
auth    required   pam_rootok.so
auth    required   pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account   required   pam_permit.so
account   required   pam_opendirectory.so no_check_shell
password  required   pam_opendirectory.so
session   required   pam_launchd.so'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55985r816399_chk'
  tag severity: 'medium'
  tag gid: 'V-252529'
  tag rid: 'SV-252529r816487_rule'
  tag stig_id: 'APPL-12-003051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-55935r816486_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
