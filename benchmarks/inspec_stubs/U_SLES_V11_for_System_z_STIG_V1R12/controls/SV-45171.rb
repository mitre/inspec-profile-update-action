control 'SV-45171' do
  title 'All shells referenced in /etc/passwd must be listed in the /etc/shells file, except any shells specified for the purpose of preventing logins.'
  desc 'The shells file lists approved default shells. It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized unsecure shell.'
  desc 'check', 'Confirm the login shells referenced in the /etc/passwd file are listed in the /etc/shells file.

Procedure:
# for USHELL in `cut -d: -f7 /etc/passwd`; do if [ $(grep -c "${USHELL}" /etc/shells) == 0 ]; then echo "${USHELL} not in /etc/shells"; fi; done

The /usr/bin/false, /bin/false, /dev/null, /sbin/nologin, /bin/sync, /sbin/halt, /sbin/shutdown, (and equivalents), and sdshell will be considered valid shells for use in the /etc/passwd file, but will not be listed in the /etc/shells file.

If a shell referenced in /etc/passwd is not listed in the shells file, excluding the above mentioned shells, this is a finding.'
  desc 'fix', 'Use the YaST > Security and Users > User and Group Management module to change the default shell of any account in error to an acceptable shell.
OR
Use the "chsh" utility or edit the /etc/passwd file and correct the error by changing the default shell of the account in error to an acceptable shell name contained in the /etc/shells file.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42516r1_chk'
  tag severity: 'medium'
  tag gid: 'V-917'
  tag rid: 'SV-45171r1_rule'
  tag stig_id: 'GEN002140'
  tag gtitle: 'GEN002140'
  tag fix_id: 'F-38569r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
