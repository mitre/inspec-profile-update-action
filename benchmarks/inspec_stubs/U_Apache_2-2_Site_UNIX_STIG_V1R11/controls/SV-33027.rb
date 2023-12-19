control 'SV-33027' do
  title 'Web client access to the content directories must be restricted to read and execute.'
  desc 'Excessive permissions for the anonymous web user account are one of the most common faults contributing to the compromise of a web server. If this user is able to upload and execute files on the web server, the organization or owner of the server will no longer have control of the asset.'
  desc 'check', 'To view the value of Alias enter the following command: 

grep "Alias" /usr/local/apache2/conf/httpd.conf 

Alias
ScriptAlias
ScriptAliasMatch

Review the results to determine the location of the files listed above. 

Enter the following command to determine the permissions of the above file: 

ls -Ll /file-path

The only accounts listed should be the web administrator, developers, and the account assigned to run the apache server service. 

If accounts that don’t need access to these directories are listed, this is a finding. 

If the permissions assigned to the account for the Apache web server service, or any group to which the Apache web server service belongs, is greater than Read & Execute (R_E), this is a finding.'
  desc 'fix', 'Assign the appropriate permissions to the applicable directories and files using the chmod command.'
  impact 0.7
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33710r2_chk'
  tag severity: 'high'
  tag gid: 'V-2258'
  tag rid: 'SV-33027r2_rule'
  tag stig_id: 'WG290 A22'
  tag gtitle: 'WG290'
  tag fix_id: 'F-29342r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
