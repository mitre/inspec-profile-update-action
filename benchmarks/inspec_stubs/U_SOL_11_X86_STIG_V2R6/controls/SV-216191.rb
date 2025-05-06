control 'SV-216191' do
  title 'Duplicate Group IDs (GIDs) must not exist for multiple groups.'
  desc 'User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.'
  desc 'check', %q(The root role is required.

Check that group IDs are unique.

# getent group | cut -f3 -d":" | sort -n | uniq -c |\
while read x ; do
[ -z "${x}" ] && break
set - $x
if [ $1 -gt 1 ]; then
grps=`getent group | nawk -F: '($3 == n) { print $1
}' n=$2 | xargs`
echo "Duplicate GID ($2): ${grps}"
fi
done

If output is produced, this is a finding.)
  desc 'fix', 'The root role is required.

Work with each respective group owner to remediate this issue and ensure that the group ownership of their files are set to an appropriate value.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17429r372955_chk'
  tag severity: 'medium'
  tag gid: 'V-216191'
  tag rid: 'SV-216191r603268_rule'
  tag stig_id: 'SOL-11.1-070120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17427r372956_fix'
  tag 'documentable'
  tag legacy: ['SV-60953', 'V-48081']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
