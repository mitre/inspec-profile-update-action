control 'SV-216418' do
  title 'Permissions on user home directories must be 750 or less permissive.'
  desc "Group-writable or world-writable user home directories may enable malicious users to steal or modify other users' data or to gain another user's system privileges."
  desc 'check', %q(The root role is required.

Check that the permissions on users' home directories are 750 or less permissive.

# for dir in `logins -ox |\
awk -F: '($8 == "PS") { print $6 }'`; do
find ${dir} -type d -prune \( -perm -g+w -o \
-perm -o+r -o -perm -o+w -o -perm -o+x \\) -ls
done

If output is created, this is finding.)
  desc 'fix', "The root role is required. 

Change the permissions on users' directories to 750 or less permissive.

# chmod 750 [directory name]"
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17654r371342_chk'
  tag severity: 'medium'
  tag gid: 'V-216418'
  tag rid: 'SV-216418r603267_rule'
  tag stig_id: 'SOL-11.1-070020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17652r371343_fix'
  tag 'documentable'
  tag legacy: ['V-48133', 'SV-61005']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
