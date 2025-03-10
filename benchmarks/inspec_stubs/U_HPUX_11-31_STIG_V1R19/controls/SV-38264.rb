control 'SV-38264' do
  title 'The .rhosts file must not be supported in PAM.'
  desc '.rhosts files are used to specify a list of hosts permitted remote access to a particular account without authenticating. The use of such a mechanism defeats strong identification and authentication requirements.'
  desc 'check', %q(Verify the remsh and rexec services have not been configured to use the PAM module:
# cat /etc/pam.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep "^rcomds" | egrep "auth|account" | egrep "libpam_unix|libpam_hpsec"

If any of the following lines are returned, this is a finding. 

rcomds auth required libpam_hpsec.so.1
rcomds auth required libpam_unix.so.1
rcomds account required libpam_hpsec.so.1
rcomds account required libpam_unix.so.1)
  desc 'fix', 'Edit /etc/pam.conf and comment/remove the "rcomds" line(s).'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36422r3_chk'
  tag severity: 'medium'
  tag gid: 'V-11989'
  tag rid: 'SV-38264r2_rule'
  tag stig_id: 'GEN002100'
  tag gtitle: 'GEN002100'
  tag fix_id: 'F-31761r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
