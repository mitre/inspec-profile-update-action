control 'SV-216184' do
  title 'There must be no user .rhosts files.'
  desc 'Even though the .rhosts files are ineffective if support is disabled in /etc/pam.conf, they may have been brought over from other systems and could contain information useful to an attacker for those other systems.'
  desc 'check', %q(The root role is required.

Check for the presence of .rhosts files.

# for dir in \
`logins -ox | awk -F: '($8 == "PS") { print $6 }'`; do
find ${dir}/.rhosts -type f -ls 2>/dev/null
done

If output is produced, this is a finding.)
  desc 'fix', 'The root role is required.

Remove any .rhosts files found.

# rm [file name]'
  impact 0.7
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17422r372934_chk'
  tag severity: 'high'
  tag gid: 'V-216184'
  tag rid: 'SV-216184r603268_rule'
  tag stig_id: 'SOL-11.1-070050'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17420r372935_fix'
  tag 'documentable'
  tag legacy: ['V-48119', 'SV-60991']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
