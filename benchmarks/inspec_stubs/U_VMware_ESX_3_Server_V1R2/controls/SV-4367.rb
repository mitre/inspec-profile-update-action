control 'SV-4367' do
  title 'The at.allow file must be owned by root, bin, or sys.'
  desc 'If the owner of the at.allow file is not set to root, bin, or sys, unauthorized users could be allowed to view or edit sensitive information contained within the file.'
  desc 'check', 'Check the owner of the at.allow file.  If the owner is not root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the owner of the at.allow file to root, bin, or sys.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8248r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4367'
  tag rid: 'SV-4367r2_rule'
  tag stig_id: 'GEN003460'
  tag gtitle: 'GEN003460'
  tag fix_id: 'F-4278r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
