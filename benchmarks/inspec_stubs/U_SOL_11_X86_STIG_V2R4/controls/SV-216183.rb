control 'SV-216183' do
  title 'Permissions on user .netrc files must be 750 or less permissive.'
  desc '.netrc files may contain unencrypted passwords that can be used to attack other systems.'
  desc 'check', %q(The root role is required.

Check that permissions on user .netrc files are 750 or less permissive.

# for dir in \
`logins -ox | awk -F: '($8 == "PS") { print $6 }'`; do
find ${dir}/.netrc -type f \( \
-perm -g+r -o -perm -g+w -o -perm -g+x -o \
-perm -o+r -o -perm -o+w -o -perm -o+x \\) \
-ls 2>/dev/null
done

If output is produced, this is a finding.)
  desc 'fix', "The root role is required. 

Change the permissions on users' .netrc files to 750 or less permissive.

# chmod 750 [file name]"
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17421r372931_chk'
  tag severity: 'medium'
  tag gid: 'V-216183'
  tag rid: 'SV-216183r603268_rule'
  tag stig_id: 'SOL-11.1-070040'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17419r372932_fix'
  tag 'documentable'
  tag legacy: ['V-48123', 'SV-60995']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
