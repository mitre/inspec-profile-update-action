control 'SV-38264' do
  title 'The .rhosts file must not be supported in PAM.'
  desc '.rhosts files are used to specify a list of hosts permitted remote access to a particular account without authenticating. The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'check', %q(# cat /etc/pam.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep "^rcomds" | egrep "auth|account" | egrep "libpam_unix|libpam_hpsec"

NOTE: The entries in /etc/pam.conf Authentication and Account management sections should be configured as follows:
# Authentication management
rcomds auth    required libpam_hpsec.so.1
rcomds auth    required libpam_unix.so.1
# Account management
rcomds account required libpam_hpsec.so.1
rcomds account required libpam_unix.so.1

The remsh and rexec services use the above entries as configuration information for authenticating users. Adding these entries in the /etc/pam.conf file informs rexec and remsh to use the standard UNIX authentication mechanism to authenticate the users, including the inspection of the .rhosts file.)
  desc 'fix', 'Edit /etc/pam.conf and comment/remove the "rcomds" line(s).'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36422r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11989'
  tag rid: 'SV-38264r1_rule'
  tag stig_id: 'GEN002100'
  tag gtitle: 'GEN002100'
  tag fix_id: 'F-31761r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECCD-2, ECCD-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
