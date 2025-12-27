control 'SV-37698' do
  title 'Management Information Base (MIB) files must have mode 0640 or less permissive.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', 'Check the modes for all Management Information Base (MIB) files on the system.

Procedure:
# find / -name *.mib 
# ls -lL <mib file>

Any file returned with a mode 0640 or less permissive is a finding.'
  desc 'fix', 'Change the mode of MIB files to 0640.

Procedure:
# chmod 0640 <mib file>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-995'
  tag rid: 'SV-37698r1_rule'
  tag stig_id: 'GEN005340'
  tag gtitle: 'GEN005340'
  tag fix_id: 'F-32000r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
