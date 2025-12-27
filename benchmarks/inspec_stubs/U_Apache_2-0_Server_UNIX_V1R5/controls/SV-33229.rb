control 'SV-33229' do
  title 'The URL-path name must be set to the file path name or the directory path name.'
  desc 'The ScriptAlias directive controls which directories the Apache server "sees" as containing scripts.  If the directive uses a URL-path name that is different than the actual file system path, the potential exists to expose the script source code.'
  desc 'check', 'Enter the following command:

grep "ScriptAlias" /usr/local/apache2/conf/httpd.conf.  

If any enabled ScriptAlias directive do not have matching URL-path and file-path or directory-path entries, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and set the ScriptAlias URL-path and file-path or directory-path entries.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33784r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26327'
  tag rid: 'SV-33229r1_rule'
  tag stig_id: 'WA00560 A22'
  tag gtitle: 'WA00560'
  tag fix_id: 'F-29427r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECND-1'
end
