control 'SV-26509' do
  title 'System audit tool executables must be group-owned by root, bin, sys, or other.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Verify the audit tools are group-owned by root, bin, sys, or other. The list of files should minimally include the following: 
audevent - Change/display event/system call status.
audfilter - Load/clear/display the audit filtering policy.
auditdp - Selectively read/write and convert/format the audit data.
audisp - Display audit records.
audomon - Audit file monitoring and size parameter setpoints.
audsys - Start/stop auditing; set/display the audit file or directory information.
userdbset - Select user to be audited.
# ls -lL /usr/sbin/aud* /usr/sbin/userdb*

If any system audit tool is not group-owned by root, bin, sys, or other, this is a finding.'
  desc 'fix', 'As root, change the file group ownership.
# chgrp root  <audit_tool_filename>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36438r2_chk'
  tag severity: 'low'
  tag gid: 'V-22371'
  tag rid: 'SV-26509r2_rule'
  tag stig_id: 'GEN002716'
  tag gtitle: 'GEN002716'
  tag fix_id: 'F-31777r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
