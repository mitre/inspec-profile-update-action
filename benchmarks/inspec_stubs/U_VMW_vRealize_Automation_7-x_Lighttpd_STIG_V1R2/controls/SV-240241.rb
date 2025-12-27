control 'SV-240241' do
  title 'Lighttpd must only enable mappings to necessary and approved scripts.'
  desc 'Lighttpd will only allow or deny script execution based on file extension. The ability to control script execution is controlled with the cgi.assign variable in lighttpd.conf. For script mappings, the ISSO must document and approve all allowable file extensions the web site allows (whitelist). The whitelist will be compared to the script mappings in Lighttpd.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Determine the scripts that are deemed necessary and approved (whitelist). 

Note: Lighttpd provides the cgi.assign parameter to specify script mappings.

Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Navigate to the cgi.assign parameter.

If cgi.assign parameter is configured with script types that are deemed for denial, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf file

Navigate to the cgi.assign parameter.

Configure the cgi.assign parameter with the scripts that are deemed necessary and approved (whitelisted).'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43474r668013_chk'
  tag severity: 'medium'
  tag gid: 'V-240241'
  tag rid: 'SV-240241r879587_rule'
  tag stig_id: 'VRAU-LI-000190'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-43433r667899_fix'
  tag 'documentable'
  tag legacy: ['SV-99913', 'V-89263']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
