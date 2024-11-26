control 'SV-216425' do
  title 'All home directories must be owned by the respective user assigned to it in /etc/passwd.'
  desc "Since the user is accountable for files stored in the user's home directory, the user must be the owner of the directory."
  desc 'check', %q(The root role is required.

Check that home directories are owned by the correct user.

# export IFS=":"; logins -uxo | while read user uid group gid gecos home rest; do result=$(find ${home} -type d -prune \! -user $user -print 2>/dev/null); 
if [ ! -z "${result}" ]; then 
echo "User: ${user}\tOwner: $(ls -ld $home | awk '{ print $3 }')";
fi;
done

If any output is produced, this is a finding.)
  desc 'fix', 'The root role is required.

Correct the owner of any directory that does not match the password file entry for that user.

# chown [user] [home directory]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17661r371363_chk'
  tag severity: 'medium'
  tag gid: 'V-216425'
  tag rid: 'SV-216425r603267_rule'
  tag stig_id: 'SOL-11.1-070090'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17659r371364_fix'
  tag 'documentable'
  tag legacy: ['V-48097', 'SV-60969']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
