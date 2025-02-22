control 'SV-257234' do
  title 'The macOS system must be configured so that the login command requires smart card authentication.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DOD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'For systems that are not using smart card authentication, this requirements is not applicable.

Verify the macOS system is configured to require smart card authentication for the login command with the following command:

/bin/cat /etc/pam.d/login 

If the text that returns does not include the line "auth sufficient pam_smartcard.so" at the TOP of the listing and "auth required pam_deny.so" as the last entry of the auth management group, this is a finding.'
  desc 'fix', 'Configure the macOS system to require smart card authentication for the login command with the following procedure:

/usr/bin/sudo /bin/cp /etc/pam.d/login /etc/pam.d/login_backup_`date "+%Y-%m-%d_%H:%M"`

Replace the contents of "/etc/pam.d/login" with the following:

# login: auth account password session
auth    sufficient    pam_smartcard.so
auth    optional    pam_krb5.so use_kcminit
auth    optional    pam_ntlm.so try_first_pass
auth    optional    pam_mount.so try_first_pass
auth    required    pam_opendirectory.so try_first_pass
auth    required    pam_deny.so
account  required    pam_nologin.so
account  required    pam_opendirectory.so
password  required    pam_opendirectory.so
session  required    pam_launchd.so
session  required    pam_uwtmp.so
session  optional    pam_mount.so'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60919r905333_chk'
  tag severity: 'medium'
  tag gid: 'V-257234'
  tag rid: 'SV-257234r905335_rule'
  tag stig_id: 'APPL-13-003050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60860r905334_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
