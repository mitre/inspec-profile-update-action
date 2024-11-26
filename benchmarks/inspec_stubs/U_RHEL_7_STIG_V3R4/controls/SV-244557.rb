control 'SV-244557' do
  title 'Red Hat Enterprise Linux operating systems version 7.2 or newer booted with a BIOS must have a unique name for the grub superusers account when booting into single-user and maintenance modes.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'For systems that use UEFI, this is Not Applicable.

For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.

Verify that a unique name is set as the "superusers" account:

# grep -iw "superusers" /boot/grub2/grub.cfg
    set superusers="[someuniquestringhere]"
    export superusers

If "superusers" is not set to a unique name or is missing a name, this is a finding.'
  desc 'fix', 'Configure the system to have a unique name for the grub superusers account.

Edit the /boot/grub2/grub.cfg file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="[someuniquestringhere]"
export superusers
password_pbkdf2 [someuniquestringhere] ${GRUB2_PASSWORD}'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-47832r744061_chk'
  tag severity: 'medium'
  tag gid: 'V-244557'
  tag rid: 'SV-244557r744063_rule'
  tag stig_id: 'RHEL-07-010483'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-47789r744062_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
