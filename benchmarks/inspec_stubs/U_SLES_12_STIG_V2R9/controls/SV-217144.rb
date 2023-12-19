control 'SV-217144' do
  title 'SUSE operating systems with a basic input/output system (BIOS) must require authentication upon booting into single-user and maintenance modes.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Verify that the SUSE operating system has set an encrypted root password. 

Note: If the system does not use a basic input/output system (BIOS) this requirement is Not Applicable.

Check that the encrypted password is set for a boot user with the following command:

# sudo cat /boot/grub2/grub.cfg | grep -i password 

password_pbkdf2 boot grub.pbkdf2.sha512.10000.VeryLongString

If the boot user password entry does not begin with "password_pbkdf2", this is a finding.'
  desc 'fix', 'Note: If the system does not use a basic input/output system (BIOS) this requirement is Not Applicable.

Configure the SUSE operating system to encrypt the boot password.

Generate an encrypted (GRUB2) password for root with the following command:

# sudo grub2-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG

Using the hash from the output, modify the "/etc/grub.d/40_custom" file with the following command to add a password for the boot user entry:

# cat << EOF
set superusers="boot"
password_pbkdf2 boot grub.pbkdf2.sha512.VeryLongString
EOF

Generate an updated "grub.conf" file with the new password using the following commands:

# sudo grub2-mkconfig --output=/tmp/grub2.cfg
# sudo mv /tmp/grub2.cfg /boot/grub2/grub.cfg'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18372r369588_chk'
  tag severity: 'medium'
  tag gid: 'V-217144'
  tag rid: 'SV-217144r603262_rule'
  tag stig_id: 'SLES-12-010430'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-18370r369589_fix'
  tag 'documentable'
  tag legacy: ['V-77143', 'SV-91839']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
