control 'SV-99923' do
  title 'Lighttpd must not use symbolic links in the Lighttpd web content directory tree.'
  desc 'A symbolic link allows a file or a directory to be referenced using a symbolic name raising a potential hazard if symbolic linkage is made to a sensitive area. When web scripts are executed and symbolic links are allowed, the Lighttpd could be allowed to access locations on the server that are outside the scope of the hosted application document root or home directory.'
  desc 'check', 'At the command prompt, execute the following command:

find /opt/vmware/share/htdocs -type l

If any files are listed, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following commands:

Note: Replace <file_name> for the name of any files that were returned.

unlink <file_name>

Repeat the commands for each file that was listed.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88965r1_chk'
  tag severity: 'high'
  tag gid: 'V-89273'
  tag rid: 'SV-99923r1_rule'
  tag stig_id: 'VRAU-LI-000215'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-96015r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
