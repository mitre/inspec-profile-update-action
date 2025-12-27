control 'SV-37252' do
  title "Local initialization files must be group-owned by the user's primary group or root."
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check user home directories for local initialization files group-owned by a group other than the user's primary group or root.

Procedure:
# FILES=" .login .cshrc .logout .profile .bash_profile .bashrc .bash_logout .env .dtprofile .dispatch .emacs .exrc";
# for PWLINE in `cut -d: -f4,6 /etc/passwd`; do HOMEDIR=$(echo ${PWLINE}|cut -d: -f2);GROUP=$(echo ${PWLINE} | cut -d: -f1);for INIFILE in $FILES;do stat -c %g/%G:%n ${HOMEDIR}/${INIFILE} 2>null|egrep -v "${GROUP}";done;done

If any file is not group-owned by root or the user's primary GID, this is a finding.)
  desc 'fix', %q(Change the group-owner of the local initialization file to the user's primary group, or root.
# chgrp <user's primary GID> <user's local initialization file>

Procedure:
# FILES=".bashrc .bash_login .bash_logout .bash_profile .cshrc .kshrc .login .logout .profile .tcshrc .env .dtprofile .dispatch .emacs .exrc";
# for PWLINE in `cut -d: -f4,6 /etc/passwd`; do HOMEDIR=$(echo ${PWLINE}|cut -d: -f2);GROUP=$(echo ${PWLINE} | cut -d: -f1);for INIFILE in $FILES;do MATCH=$(stat -c %g/%G:%n ${HOMEDIR}/${INIFILE} 2>null|egrep -c -v "${GROUP}");if [ $MATCH != 0 ] ; then chgrp ${GROUP} ${HOMEDIR}/${INIFILE};fi;done;done)
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22361'
  tag rid: 'SV-37252r1_rule'
  tag stig_id: 'GEN001870'
  tag gtitle: 'GEN001870'
  tag fix_id: 'F-31199r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
