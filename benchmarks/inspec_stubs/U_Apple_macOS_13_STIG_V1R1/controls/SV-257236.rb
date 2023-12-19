control 'SV-257236' do
  title 'The macOS system must be configured so that the sudo command requires smart card authentication.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DOD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'For systems that are not using smart card authentication, this requirement is not applicable.

Verify the macOS system is configured to require smart card authentication for the "sudo" command with the following command:

/bin/cat /etc/pam.d/sudo 

If the text that returns does not include the line, "auth sufficient pam_smartcard.so" at the top of the listing and "auth required pam_deny.so" as the last entry of the auth management group, this is a finding.'
  desc 'fix', 'Configure the macOS system to require smart card authentication for the sudo command with the following procedure:

/usr/bin/sudo /bin/cp /etc/pam.d/login /etc/pam.d/sudo_backup_`date "+%Y-%m-%d_%H:%M"`

Replace the contents of "/etc/pam.d/sudo" with the following:

# sudo: auth account password session
auth    sufficient    pam_smartcard.so
auth    required    pam_opendirectory.so
auth    required    pam_deny.so
account    required    pam_permit.so
password    required    pam_deny.so
session    required    pam_permit.so'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60921r905339_chk'
  tag severity: 'medium'
  tag gid: 'V-257236'
  tag rid: 'SV-257236r905341_rule'
  tag stig_id: 'APPL-13-003052'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-60862r905340_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
