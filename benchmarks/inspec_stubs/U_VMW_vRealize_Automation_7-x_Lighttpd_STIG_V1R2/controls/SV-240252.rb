control 'SV-240252' do
  title 'Lighttpd must have the latest version installed.'
  desc 'Allowing malicious users the capability to traverse server directory tree can create significant vulnerabilities. Such information and the contents of files listed should not be normally readable by the web users as they often contain information relevant to the configuration and security of the web service.

Older version of Lighttpd, up to 1.4.34, have been found to be vulnerable to directory traversal and subsequent directory traversal exploits. See CVE-2014-2324 for details.'
  desc 'check', 'At the command prompt, execute the following command:

/opt/vmware/sbin/vami-lighttpd -v

If the Lighttpd version does not have the latest version installed, this is a finding.'
  desc 'fix', 'Install the latest version.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43485r667931_chk'
  tag severity: 'high'
  tag gid: 'V-240252'
  tag rid: 'SV-240252r879631_rule'
  tag stig_id: 'VRAU-LI-000260'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-43444r667932_fix'
  tag 'documentable'
  tag legacy: ['SV-99935', 'V-89285']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
