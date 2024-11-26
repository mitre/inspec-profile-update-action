control 'SV-218257' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19732r554108_chk'
  tag severity: 'low'
  tag gid: 'V-218257'
  tag rid: 'SV-218257r603259_rule'
  tag stig_id: 'GEN001080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19730r554109_fix'
  tag 'documentable'
  tag legacy: ['V-1062', 'SV-64441']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
