control 'SV-37494' do
  title 'Files executed through a mail aliases file must have mode 0755 or less permissive.'
  desc 'If a file executed through a mail aliases file has permissions greater than 0755, it can be modified by an unauthorized user and may contain malicious code or instructions potentially compromising the system.'
  desc 'fix', 'Use the chmod command to change the access permissions for files executed from the alias file. 

For example:
# chmod 0755 filename'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-834'
  tag rid: 'SV-37494r2_rule'
  tag stig_id: 'GEN004420'
  tag gtitle: 'GEN004420'
  tag fix_id: 'F-31403r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
