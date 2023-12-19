control 'SV-240242' do
  title 'Lighttpd must have resource mappings set to disable the serving of certain file types.'
  desc 'Resource mapping is the process of tying a particular file type to a process in Lighttpd that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

Lighttpd provides the url.access-deny parameter to specify a blacklist of file types which should be denied.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine the file types (blacklist) that are deemed for denial. 
 
Note: Lighttpd provides the url.access-deny parameter to specify the blacklist of files.

Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Navigate to the url.access-deny parameter.

If url.access-deny parameter is not configured with the file types that are blacklisted, this is a finding.

If url.access-deny parameter is not set properly, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Navigate to the url.access-deny parameter.

Configure the url.access-deny parameter with the file types that are blacklisted.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43475r668015_chk'
  tag severity: 'medium'
  tag gid: 'V-240242'
  tag rid: 'SV-240242r879587_rule'
  tag stig_id: 'VRAU-LI-000195'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-43434r667902_fix'
  tag 'documentable'
  tag legacy: ['SV-99915', 'V-89265']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
