control 'SV-35057' do
  title 'The root file system must employ journaling or another mechanism ensuring file system consistency.'
  desc 'File system journaling, or logging, can allow reconstruction of file system data after a system crash, thus, preserving the integrity of data that may have otherwise been lost. Journaling file systems typically do not require consistency checks upon booting after a crash, which can improve system availability. Some file systems employ other mechanisms to ensure consistency which also satisfy this requirement.'
  desc 'fix', 'Implement file system journaling for the root file system, or use a file system that uses other mechanisms to ensure file system consistency. If the root file system supports journaling, enable it. If the file system does not support journaling or another mechanism to ensure file system consistency, a migration to a different file system will be necessary.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-4304'
  tag rid: 'SV-35057r1_rule'
  tag stig_id: 'GEN003640'
  tag gtitle: 'GEN003640'
  tag fix_id: 'F-30232r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000553']
  tag nist: ['CP-10 (2)']
end
