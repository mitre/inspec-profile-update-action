control 'SV-254128' do
  title 'Nutanix AOS must be configured with an encrypted boot password for root.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Confirm Nutanix AOS is configured to enforce approved authorizations for logical access to information and system resources.

$ sudo grep -i password /boot/grub/grub.conf
password [superusers-account] [password-hash]

If the root password entry does not begin with "password", this is a finding.

$ sudo grep -i execstart /usr/lib/systemd/system/rescue.service | grep -i sulogin
ExecStart=-/bin/sh -c "/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default"

If "ExecStart" does not have "/usr/sbin/sulogin" as an option, this is a finding.'
  desc 'fix', %q(Configure the system to encrypt the boot password for root. 

1. Use the following command as root to generate a grub sha512 password hash: python -c 'import crypt; print crypt.crypt("password", crypt.mksalt(crypt.METHOD_SHA512))' Replacing "password" with the password string desired for grub. 

2. Edit the /boot/grub/grub.conf file as root and add the following line above the title line: 'password --encrypted [password-hash]', replacing [password-hash] with the hash result of the python command output.)
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57613r846470_chk'
  tag severity: 'low'
  tag gid: 'V-254128'
  tag rid: 'SV-254128r846472_rule'
  tag stig_id: 'NUTX-OS-000160'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-57564r846471_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
