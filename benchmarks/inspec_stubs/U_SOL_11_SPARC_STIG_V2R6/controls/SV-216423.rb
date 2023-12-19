control 'SV-216423' do
  title 'Users must have a valid home directory assignment.'
  desc 'All users must be assigned a home directory in the passwd file. Failure to have a home directory may result in the user being put in the root directory.'
  desc 'check', %q(The root role is required.

Determine if each user has a valid home directory.

# logins -xo | while read line; do
     user=`echo ${line} | awk -F: '{ print $1 }'`
     home=`echo ${line} | awk -F: '{ print $6 }'`
     if [ -z "${home}" ]; then
        echo ${user}
     fi
done

If output is produced, this is a finding.)
  desc 'fix', 'The root role is required.

Correct or justify any items discovered in the check step. Determine if there exists any users who are in passwd but do not have a home directory, and work with those users to determine the best course of action in accordance with site policy.  This generally means deleting the user or creating a valid home directory.'
  impact 0.3
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17659r371357_chk'
  tag severity: 'low'
  tag gid: 'V-216423'
  tag rid: 'SV-216423r603267_rule'
  tag stig_id: 'SOL-11.1-070070'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17657r371358_fix'
  tag 'documentable'
  tag legacy: ['SV-60981', 'V-48109']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
