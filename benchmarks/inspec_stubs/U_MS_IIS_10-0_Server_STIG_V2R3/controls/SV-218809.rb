control 'SV-218809' do
  title 'The IIS 10.0 web server Indexing must only index web content.'
  desc 'The indexing service can be used to facilitate a search function for websites. Enabling indexing may facilitate a directory traversal exploit and reveal unwanted information to a malicious user. Indexing must be limited to web document directories only.'
  desc 'check', %q(Access the IIS 10.0 Web Server.

Access an administrator command prompt and type "regedit <enter>" to access the server's registry.

Navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ContentIndex\Catalogs\.

If this key exists, then indexing is enabled. 

If the key does not exist, this check is Not Applicable.

Review the Catalog keys to determine if directories other than web document directories are being indexed.

If so, this is a finding.)
  desc 'fix', 'Run MMC.

Add the Indexing Service snap-in.

Edit the indexed directories to only include web document directories.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-20281r310902_chk'
  tag severity: 'medium'
  tag gid: 'V-218809'
  tag rid: 'SV-218809r561041_rule'
  tag stig_id: 'IIST-SV-000139'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-20279r310903_fix'
  tag 'documentable'
  tag legacy: ['SV-109257', 'V-100153']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
