control 'SV-40806' do
  title 'The /etc/shells (or equivalent) file must exist.'
  desc 'The shells file (or equivalent) lists approved default shells.  It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized shell that may not be secure.'
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
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-916'
  tag rid: 'SV-40806r1_rule'
  tag stig_id: 'GEN002120'
  tag gtitle: 'GEN002120'
  tag fix_id: 'F-34658r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
