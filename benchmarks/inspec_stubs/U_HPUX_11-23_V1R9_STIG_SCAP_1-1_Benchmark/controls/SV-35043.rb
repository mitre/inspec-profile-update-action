control 'SV-35043' do
  title 'Files executed through a mail aliases file must have mode 0755 or less permissive.'
  desc 'If a file executed through a mail alias file has permissions greater than 0755, it can be modified by an unauthorized user and may contain malicious code or instructions possibly compromising the system.'
  desc 'fix', 'Use the chmod command to change the access permissions 
for files executed from the aliases file. For example:
# chmod 0755 <path/file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-834'
  tag rid: 'SV-35043r1_rule'
  tag stig_id: 'GEN004420'
  tag gtitle: 'GEN004420'
  tag fix_id: 'F-31930r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
