control 'SV-37380' do
  title 'The root shell must be located in the / file system.'
  desc 'To ensure the root shell is available in repair and administrative modes, the root shell must be located in the / file system.'
  desc 'check', %q(Determine if root's shell executable resides on a dedicated file system.

Procedure:
Find the location of the root user's shell

# grep "^root" /etc/passwd|cut -d: -f7|cut -d/ -f2

The result is the top level directory under / where the shell resides (e.g., usr)
Check if it is on a dedicated file system.

# grep /<top level directory> /etc/fstab

If /<top level directory> is on a dedicated file system, this is a finding.)
  desc 'fix', "Change the root account's shell to one present on the / file system. 

Procedure:
Edit /etc/passwd and change the shell for the root account to one present on the / file system (such as /bin/sh, assuming /bin is not on a separate file system). If the system does not store shell configuration in the /etc/passwd file, consult vendor documentation for the correct procedure for the system."
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36067r2_chk'
  tag severity: 'low'
  tag gid: 'V-1062'
  tag rid: 'SV-37380r1_rule'
  tag stig_id: 'GEN001080'
  tag gtitle: 'GEN001080'
  tag fix_id: 'F-31311r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
