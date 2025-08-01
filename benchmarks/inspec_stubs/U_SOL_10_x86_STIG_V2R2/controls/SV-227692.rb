control 'SV-227692' do
  title 'The /etc/shells (or equivalent) file must exist.'
  desc 'The shells file (or equivalent) lists approved default shells.  It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized shell that may not be secure.'
  desc 'check', 'Verify /etc/shells exists.
# ls -l /etc/shells
If the file does not exist, this is a finding.'
  desc 'fix', 'Create a /etc/shells file containing a list of valid system shells.  The list below contains the default shells from the shells(4) man page.

Procedure (the command is 24 lines long):
cat >/etc/shells <<EOF
/bin/bash
/bin/csh
/bin/jsh
/bin/ksh
/bin/pfcsh
/bin/pfksh
/bin/pfsh
/bin/sh
/bin/tcsh
/bin/zsh
/sbin/jsh
/sbin/sh
/usr/bin/bash
/usr/bin/csh
/usr/bin/jsh
/usr/bin/ksh
/usr/bin/pfcsh
/usr/bin/pfksh
/usr/bin/pfsh
/usr/bin/sh
/usr/bin/tcsh
/usr/bin/zsh
EOF'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36457r602974_chk'
  tag severity: 'medium'
  tag gid: 'V-227692'
  tag rid: 'SV-227692r603266_rule'
  tag stig_id: 'GEN002120'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36421r602975_fix'
  tag 'documentable'
  tag legacy: ['V-916', 'SV-40806']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
