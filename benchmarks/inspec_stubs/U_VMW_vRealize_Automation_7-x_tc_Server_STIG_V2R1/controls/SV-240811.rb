control 'SV-240811' do
  title 'tc Server HORIZON web server application directories must not be accessible to anonymous user.'
  desc 'In order to properly monitor the changes to the web server and the hosted applications, logging must be enabled. Along with logging being enabled, each record must properly contain the changes made and the names of those who made the changes.

Allowing anonymous users the capability to change the web server or the hosted application will not generate proper log information that can then be used for forensic reporting in the case of a security issue. Allowing anonymous users to make changes will also grant change capabilities to anybody without forcing a user to authenticate before the changes can be made.'
  desc 'check', "At the command prompt, execute the following command:

ls -alR /opt/vmware/horizon/workspace | grep -E '^-' | awk '$1 !~ /---$/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following command:

chmod 750 <file_name>

Repeat the command for each file that was returned.

Note: Replace <file_name> for the name of the file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44044r674175_chk'
  tag severity: 'high'
  tag gid: 'V-240811'
  tag rid: 'SV-240811r674177_rule'
  tag stig_id: 'VRAU-TC-000490'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-44003r674176_fix'
  tag 'documentable'
  tag legacy: ['SV-100703', 'V-90053']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
