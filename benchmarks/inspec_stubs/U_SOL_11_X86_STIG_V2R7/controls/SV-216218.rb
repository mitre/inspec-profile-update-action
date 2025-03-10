control 'SV-216218' do
  title 'The system must require authentication before allowing modification of the boot devices or menus. Secure the GRUB Menu (Intel).'
  desc 'The flexibility that GRUB provides creates a security risk if its configuration is modified by an unauthorized user. The failsafe menu entry needs to be secured in the same environments that require securing the systems firmware to avoid unauthorized removable media boots.'
  desc 'check', 'This check applies to X86 systems only.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

# grep source /rpool/boot/grub/grub.cfg
source $prefix/custom.cfg

If the output does not contain "source $prefix/custom.cfg" on a line of its own, this is a finding.

# grep superusers /rpool/boot/grub/custom.cfg.
# grep password_pbkdf2 /rpool/boot/grub/custom.cfg

If no superuser name and password are defined, this is a finding.'
  desc 'fix', 'The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Update GRUB to use a custom configuration file.

# pfedit /rpool/boot/grub/grub.cfg
Insert the line:
source $prefix/custom.cfg

Create a password hash.

# /usr/lib/grub2/bios/bin/grub-mkpasswd-pbkdf2
Enter password: 
Reenter password: 
Your PBKDF2 is .......
Copy the long password hash in its entirety.

# pfedit /rpool/boot/grub/custom.cfg
Insert the lines:
set superusers="[username]"
password_pbkdf2 [username] [password hash]

Restart the system.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17456r373036_chk'
  tag severity: 'low'
  tag gid: 'V-216218'
  tag rid: 'SV-216218r603268_rule'
  tag stig_id: 'SOL-11.1-080140'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17454r373037_fix'
  tag 'documentable'
  tag legacy: ['V-48001', 'SV-60873']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
