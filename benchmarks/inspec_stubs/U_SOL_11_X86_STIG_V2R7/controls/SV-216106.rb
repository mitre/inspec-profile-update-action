control 'SV-216106' do
  title 'The default umask for system and users must be 077.'
  desc 'Setting a very secure default value for umask ensures that users make a conscious choice about their file permissions.'
  desc 'check', 'The root role is required.

Determine if the default umask is configured properly.

# grep -i "^UMASK=" /etc/default/login

If "UMASK=077" is not displayed, this is a finding.

Check local initialization files:
# cut -d: -f1 /etc/passwd | xargs -n1 -iUSER sh -c "grep umask ~USER/.*"

If this command does not output a line indicating "umask 077" for each user, this is a finding.'
  desc 'fix', 'The root role is required.

Edit local and global initialization files containing "umask" and change them to use 077.

# pfedit /etc/default/login

Insert the line
UMASK=077

# pfedit [user initialization file]

Insert the line
umask 077'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17344r372700_chk'
  tag severity: 'medium'
  tag gid: 'V-216106'
  tag rid: 'SV-216106r603268_rule'
  tag stig_id: 'SOL-11.1-040250'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17342r372701_fix'
  tag 'documentable'
  tag legacy: ['SV-60933', 'V-48061']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
