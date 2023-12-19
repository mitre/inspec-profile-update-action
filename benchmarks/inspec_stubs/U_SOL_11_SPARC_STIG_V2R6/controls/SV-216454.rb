control 'SV-216454' do
  title 'The system must require passwords to change the boot device settings. (SPARC)'
  desc 'Setting the EEPROM password helps prevent attackers who gain physical access to the system console from booting from an external device (such as a CD-ROM or floppy).'
  desc 'check', 'This check applies only to SPARC-based systems.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine if the EEPROM security mode on SPARC-based systems is configured correctly.

# eeprom security-mode

If the output of this command is not "security-mode=command", this is a finding.'
  desc 'fix', 'The root role is required.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

# eeprom security-mode=command


After entering the command above, the administrator will be prompted for a password. This password will be required to authorize any future command issued at boot-level on the system (the ok or > prompt) except for the normal multi-user boot command (i.e., the system will be able to reboot unattended).

Write down the password and store it in a secure location.'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17690r371450_chk'
  tag severity: 'low'
  tag gid: 'V-216454'
  tag rid: 'SV-216454r603267_rule'
  tag stig_id: 'SOL-11.1-080130'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17688r371451_fix'
  tag 'documentable'
  tag legacy: ['SV-60875', 'V-48003']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
