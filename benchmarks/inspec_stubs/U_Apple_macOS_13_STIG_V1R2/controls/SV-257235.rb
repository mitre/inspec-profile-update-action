control 'SV-257235' do
  title 'The macOS system must be configured so that the su command requires smart card authentication.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DOD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'For systems that are not using smart card authentication, this requirement is not applicable.

Verify the macOS system is configured to require smart card authentication for the "su" command with the following command:

/bin/cat /etc/pam.d/su

If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the TOP of the listing and the next line is not "auth required pam_rootok.so", this is a finding.'
  desc 'fix', 'Configure the macOS system to require smart card authentication for the su command with the following procedure:

/usr/bin/sudo /bin/cp /etc/pam.d/su /etc/pam.d/su_backup_`date "+%Y-%m-%d_%H:%M"`

Replace the contents of "/etc/pam.d/su" with the following:

# su: auth account session
auth    sufficient    pam_smartcard.so
auth    required    pam_rootok.so
account    required    pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account   required    pam_opendirectory.so no_check_shell
password  required    pam_opendirectory.so
session   required    pam_launchd.so'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60920r905336_chk'
  tag severity: 'medium'
  tag gid: 'V-257235'
  tag rid: 'SV-257235r905338_rule'
  tag stig_id: 'APPL-13-003051'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60861r905337_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
