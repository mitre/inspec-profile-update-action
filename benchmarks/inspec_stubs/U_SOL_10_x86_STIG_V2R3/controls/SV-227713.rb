control 'SV-227713' do
  title 'The system and user default umask must be 077.'
  desc 'The umask controls the default access mode assigned to newly created files.  An umask of 077 limits new files to mode 700 or less permissive.  Although umask can be represented as a 4-digit number, the first digit representing special access modes is typically ignored or required to be 0.  This requirement applies to the globally configured system defaults and the user defaults for each account on the system.'
  desc 'check', 'NOTE: The following commands must be run in the BASH shell.

Check global configuration:
# find /etc -type f | xargs grep -i umask		

Check local initialization files:
# cut -d: -f6 /etc/passwd | xargs -n1 -iHOMEDIR sh -c "grep umask HOMEDIR/.*"

If the system and user default umask is not 077, this a finding.

Note: If the default umask is 000 or allows for the creation of world writable files this becomes a CAT I finding..'
  desc 'fix', 'Edit the /etc/default/login file for Solaris. Set the variable UMASK=077.

Edit local and global initialization files containing "umask" and change them to use "077".'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29875r488723_chk'
  tag severity: 'medium'
  tag gid: 'V-227713'
  tag rid: 'SV-227713r603266_rule'
  tag stig_id: 'GEN002560'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29863r488724_fix'
  tag 'documentable'
  tag legacy: ['V-808', 'SV-28641']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
