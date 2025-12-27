control 'SV-791' do
  title 'The NIS/NIS+/yp command files must have mode 0755 or less permissive.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security.  Unauthorized modification of these files could compromise these processes and the system."
  desc 'check', 'Check the mode of the NIS/NIS+/yp files.  Consult vendor documentation to determine the location of these files.

Procedure (example):
# ls -lL /path/to/file

If any such file has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of NIS/NIS+/yp files to 0755 or less permissive.

Procedure (example):
# chmod 0755 <filename>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8013r2_chk'
  tag severity: 'medium'
  tag gid: 'V-791'
  tag rid: 'SV-791r2_rule'
  tag stig_id: 'GEN001360'
  tag gtitle: 'GEN001360'
  tag fix_id: 'F-945r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
