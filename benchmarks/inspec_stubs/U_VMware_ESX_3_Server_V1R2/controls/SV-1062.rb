control 'SV-1062' do
  title 'The root shell must be located in the / file system.'
  desc 'To ensure the root shell is available in repair and administrative modes, the root shell must be located in the / file system.'
  desc 'check', %q(Determine if /usr has a dedicated file system.

Procedure:
# grep /usr /etc/fstab

If /usr is on a dedicated file system, check the location of root's default shell.

Procedure:
# grep "^root:" /etc/passwd | grep ":/usr"

If the root shell is found to be on a /usr dedicated file system, this is a finding.)
  desc 'fix', "Change the root account's shell to one present on the / file system.

Procedure:
Edit /etc/passwd and change the shell for the root account to one present on the / file system (such as /bin/sh, assuming /bin is not on a separate file system). If the system does not store shell configuration in the /etc/passwd file, consult vendor documentation for the correct procedure for the system."
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-822r2_chk'
  tag severity: 'low'
  tag gid: 'V-1062'
  tag rid: 'SV-1062r2_rule'
  tag stig_id: 'GEN001080'
  tag gtitle: 'GEN001080'
  tag fix_id: 'F-1216r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
