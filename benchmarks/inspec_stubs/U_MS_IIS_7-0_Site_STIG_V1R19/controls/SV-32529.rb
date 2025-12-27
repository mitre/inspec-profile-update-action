control 'SV-32529' do
  title 'Web content directories must not be anonymously shared.'
  desc 'Anonymously shared directories are exposed to unnecessary risk. Any unnecessary exposure increases the risk that an intruder could exploit this access and compromise the web content or cause web server performance problems.'
  desc 'check', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click Edit Permissions on the Actions Pane.
4. Click the Sharing tab.
5. If there are any anonymous shares under Network File and Folder sharing, this is a finding.'
  desc 'fix', '1. Open the IIS Manager.
2. Click the site name under review.
3. Click Edit Permissions on the Actions Pane.
4. Select the Sharing button.
5. Click Share and then click stop sharing.'
  impact 0.5
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32831r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2226'
  tag rid: 'SV-32529r2_rule'
  tag stig_id: 'WG210 IIS7'
  tag gtitle: 'WG210'
  tag fix_id: 'F-29056r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
