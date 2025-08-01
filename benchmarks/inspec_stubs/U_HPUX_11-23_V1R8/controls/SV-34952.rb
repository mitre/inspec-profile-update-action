control 'SV-34952' do
  title 'The /etc/shells (or equivalent) file must exist.'
  desc 'The shells file (or equivalent) lists approved default shells.  It helps provide layered defense to the security approach by ensuring users cannot change their default shell to an unauthorized, unsecure shell.'
  desc 'check', 'Verify /etc/shells exists.
# ls -l /etc/shells

If the file does not exist, this is a finding.'
  desc 'fix', 'Create /etc/shells file containing a list of valid system shells. Consult vendor documentation for an appropriate list of system shells.

Procedure:
Typical installed shells include:
/sbin/sh
/usr/bin/sh
/usr/bin/rsh
/usr/bin/ksh
/usr/bin/rksh
/usr/bin/csh
/usr/bin/keysh

# echo "/sbin/sh" >> /etc/shells

(Repeat as necessary for all existing shell programs.)'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36410r1_chk'
  tag severity: 'medium'
  tag gid: 'V-916'
  tag rid: 'SV-34952r1_rule'
  tag stig_id: 'GEN002120'
  tag gtitle: 'GEN002120'
  tag fix_id: 'F-31748r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
