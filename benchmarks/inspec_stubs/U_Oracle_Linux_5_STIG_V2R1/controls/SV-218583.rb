control 'SV-218583' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20058r555947_chk'
  tag severity: 'medium'
  tag gid: 'V-218583'
  tag rid: 'SV-218583r603259_rule'
  tag stig_id: 'GEN005340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20056r555948_fix'
  tag 'documentable'
  tag legacy: ['V-995', 'SV-63429']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
