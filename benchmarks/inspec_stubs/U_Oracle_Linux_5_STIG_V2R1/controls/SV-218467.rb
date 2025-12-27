control 'SV-218467' do
  title 'The at.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.allow file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', '# ls -lL /etc/at.allow
If the at.allow file is not owned by root, sys, or bin, this is a finding.'
  desc 'fix', 'Change the owner of the at.allow file.
# chown root /etc/at.allow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19942r562555_chk'
  tag severity: 'medium'
  tag gid: 'V-218467'
  tag rid: 'SV-218467r603259_rule'
  tag stig_id: 'GEN003460'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19940r562556_fix'
  tag 'documentable'
  tag legacy: ['V-4367', 'SV-64319']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
