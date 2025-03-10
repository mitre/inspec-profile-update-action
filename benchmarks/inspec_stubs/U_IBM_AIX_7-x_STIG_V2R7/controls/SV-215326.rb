control 'SV-215326' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', 'The following system library directories need to be checked:
/usr/lib/security/
/usr/lib/methods/

Determine if any system library file has an extended ACL by running the follow script:

find /usr/lib/security /usr/lib/methods/ -type f | while read file
do
aclget -o /tmp/111.acl $file > /dev/null 2>&1
if [ $? -eq 0 ]; then
grep -e "[[:space:]]enabled$" /tmp/111.acl > /dev/null 2>&1
if [ $? -eq 0 ]; then
echo "$file has ACL"
fi
fi
done

If the above script yield any output, this is a finding.'
  desc 'fix', 'Remove the extended ACL(s) from the system library file(s) and disable extended permissions using the follow script:

find /usr/lib/security /usr/lib/methods/ -type f | while read file
do
aclget -o /tmp/111.acl $file > /dev/null 2>&1
if [ $? -eq 0 ]; then
grep -e "[[:space:]]enabled$" /tmp/111.acl > /dev/null 2>&1
if [ $? -eq 0 ]; then
echo "Removing ACL from "$file
cat /tmp/111.acl | head -n9 > /tmp/222.acl
echo "    disabled" >> /tmp/222.acl
aclput -i /tmp/222.acl $file
fi
fi
done'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16524r294429_chk'
  tag severity: 'medium'
  tag gid: 'V-215326'
  tag rid: 'SV-215326r508663_rule'
  tag stig_id: 'AIX7-00-003010'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-16522r294430_fix'
  tag 'documentable'
  tag legacy: ['SV-101579', 'V-91481']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
