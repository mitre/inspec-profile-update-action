control 'SV-45153' do
  title 'Local initialization files must be group-owned by the users primary group or root.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check user home directories for local initialization files group-owned by a group other than the user's primary group or root.

Procedure:
# ls –a /<users home directory> | grep “^\.” | awk '{if ((!($1=="."))&&(!($1==".."))) print}' | xargs ls –ld

If any file is not group-owned by root or the user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group-owner of the local initialization file to the user's primary group, or root.
# chgrp <user's primary GID> <user's local initialization file>

Procedure:
for PWLINE in $(cut -d: -f4,6 /etc/passwd); do HOMEDIR=${PWLINE##*:}; GROUP=${PWLINE%%:*}; FILES=$(find ${HOMEDIR} ! -fstype nfs -type f -name '\.*'); for INIFILE in ${FILES}; do GID=$(stat -c %g ${INIFILE}); test "$GROUP" = "${GID}" || chgrp ${GROUP} ${INIFILE}; done; done)
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42496r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22361'
  tag rid: 'SV-45153r1_rule'
  tag stig_id: 'GEN001870'
  tag gtitle: 'GEN001870'
  tag fix_id: 'F-38549r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
