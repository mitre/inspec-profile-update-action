control 'SV-32379' do
  title 'Indexing Services must only index web content.'
  desc 'The indexing service can be used to facilitate a search function for web-sites. Enabling indexing may facilitate a directory traversal exploit and reveal unwanted information to a malicious user. Indexing must be limited to web document directories only.'
  desc 'check', '1. Start regedit.
2. Navigate to KEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\ContentIndex\\Catalogs\\.
3. If this key exists then indexing is enabled; if the key does not exist then this check is N/A.
4. Review the Catalogs keys to determine if directories other than web document directories are being indexed. If so, this is a finding.'
  desc 'fix', '1. Run MMC.
2. Add the Indexing Service snap-in.
3. Edit the indexed directories to only include web document directories.'
  impact 0.3
  ref 'DPMS Target IIS Web Site 7'
  tag check_id: 'C-32769r1_chk'
  tag severity: 'low'
  tag gid: 'V-3963'
  tag rid: 'SV-32379r2_rule'
  tag stig_id: 'WA000-WI070 IIS7'
  tag gtitle: 'WA000-WI070'
  tag fix_id: 'F-29020r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
