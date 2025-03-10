control 'SV-35178' do
  title 'Management Information Base (MIB) files must have mode 0640 or less permissive.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', 'Check the modes for all MIB files on the system.
# find / -type f -name *.mib -exec ls -lL {} \\;

If any file is returned without a mode 0640 or less permissive, this is a finding.'
  desc 'fix', 'Change the mode of MIB files to 0640.
# chmod 0640 <mib file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36613r1_chk'
  tag severity: 'medium'
  tag gid: 'V-995'
  tag rid: 'SV-35178r1_rule'
  tag stig_id: 'GEN005340'
  tag gtitle: 'GEN005340'
  tag fix_id: 'F-31979r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
