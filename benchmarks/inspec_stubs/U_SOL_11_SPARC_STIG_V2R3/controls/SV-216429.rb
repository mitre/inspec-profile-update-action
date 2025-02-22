control 'SV-216429' do
  title 'Reserved UIDs 0-99 must only be used by system accounts.'
  desc 'If a user is assigned a UID that is in the reserved range, even if it is not presently in use, security exposures can arise if a subsequently installed application uses the same UID.'
  desc 'check', %q(The root role is required.

Check that reserved UIDs are not assigned to non-system users.

Determine the OS version you are currently securing:
# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:
# logins -so | awk -F: '{ print $1 }' | while read user; do
found=0
for tUser in root daemon bin sys adm dladm netadm netcfg \
ftp dhcpserv sshd smmsp gdm zfssnap aiuser \
polkitd ikeuser lp openldap webservd unknown \
uucp nuucp upnp xvm mysql postgres svctag \
pkg5srv nobody noaccess nobody4; do
if [ ${user} = ${tUser} ]; then
found=1 
fi
done
if [ $found -eq 0 ]; then
echo "Invalid User with Reserved UID: ${user}"
fi
done

If output is produced without justification and documentation in accordance with site policy, this is a finding.

For Solaris 11.4 or newer:
# logins -so | awk -F: '{ print $1 }' | while read user; do
found=0
for tUser in root daemon bin sys adm dladm netadm \
netcfg dhcpserv sshd smmsp gdm zfssnap aiuser _polkitd \
ikeuser lp openldap webservd unknown \
uucp nuucp upnp xvm mysql postgres svctag \
pkg5srv nobody noaccess nobody4; do
if [ ${user} = ${tUser} ]; then
found=1
fi
done
if [ $found -eq 0 ]; then
echo "Invalid User with Reserved UID: ${user}"
fi
done

If output is produced without justification and documentation in accordance with site policy, this is a finding.)
  desc 'fix', 'The root role is required.

Correct or justify any items discovered in the Check step. Determine if there are any accounts using these reserved UIDs, and work with their owners to determine the best course of action in accordance with site policy. This may require deleting users or changing UIDs for users.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17665r462493_chk'
  tag severity: 'medium'
  tag gid: 'V-216429'
  tag rid: 'SV-216429r603267_rule'
  tag stig_id: 'SOL-11.1-070130'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17663r462494_fix'
  tag 'documentable'
  tag legacy: ['SV-60949', 'V-48077']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
