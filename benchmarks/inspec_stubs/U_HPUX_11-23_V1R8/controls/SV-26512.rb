control 'SV-26512' do
  title 'System audit tool executables must have mode 0750 or less permissive.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Verify the audit tools file permissions. The list of files should minimally include the following: 
audevent - Change/display event/system call status.
audfilter - Load/clear/display the audit filtering policy.
auditdp - Selectively read/write and convert/format the audit data.
audisp - Display audit records.
audomon - Audit file monitoring and size parameter setpoints.
audsys - Start/stop auditing; set/display the audit file or directory information.
userdbset - Select user to be audited.
# ls -lL /usr/sbin/aud* /usr/sbin/userdb*

If any system audit tool has a file permissions greater than 0750, this is a finding.'
  desc 'fix', 'As root, change the file permissions.
# chmod 0750 <audit tool executable>'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36439r2_chk'
  tag severity: 'low'
  tag gid: 'V-22372'
  tag rid: 'SV-26512r2_rule'
  tag stig_id: 'GEN002717'
  tag gtitle: 'GEN002717'
  tag fix_id: 'F-31778r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
