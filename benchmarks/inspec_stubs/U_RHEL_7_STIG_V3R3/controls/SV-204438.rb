control 'SV-204438' do
  title 'Red Hat Enterprise Linux operating systems version 7.2 or newer with a Basic Input/Output System (BIOS) must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'For systems that use UEFI, this is Not Applicable.

For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.

Check to see if an encrypted root password is set. On systems that use a BIOS, use the following command:

# grep -iw grub2_password /boot/grub2/user.cfg
GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]

If the root password does not begin with "grub.pbkdf2.sha512", this is a finding.

Verify that the "root" account is set as the "superusers":

# grep -iw "superusers" /boot/grub2/grub.cfg
    set superusers="root"
    export superusers

If "superusers" is not set to "root", this is a finding.'
  desc 'fix', 'Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.
  
# grub2-setpassword
Enter password:
Confirm password:

Edit the /boot/grub2/grub.cfg file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="root"
export superusers'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4562r88506_chk'
  tag severity: 'high'
  tag gid: 'V-204438'
  tag rid: 'SV-204438r603261_rule'
  tag stig_id: 'RHEL-07-010482'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-4562r88507_fix'
  tag 'documentable'
  tag legacy: ['SV-95717', 'V-81005']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
