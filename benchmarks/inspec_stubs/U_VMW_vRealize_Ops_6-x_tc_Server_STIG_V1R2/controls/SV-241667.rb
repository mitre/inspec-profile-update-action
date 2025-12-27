control 'SV-241667' do
  title 'tc Server CaSa web server application directories must not be accessible to anonymous user.'
  desc 'In order to properly monitor the changes to the web server and the hosted applications, logging must be enabled. Along with logging being enabled, each record must properly contain the changes made and the names of those who made the changes.

Allowing anonymous users the capability to change the web server or the hosted application will not generate proper log information that can then be used for forensic reporting in the case of a security issue. Allowing anonymous users to make changes will also grant change capabilities to anybody without forcing a user to authenticate before the changes can be made.'
  desc 'check', "At the command prompt, execute the following commands:

cd /usr/lib/vmware-casa/casa-webapp

ls -alR bin lib conf | grep -E '^-' | awk '$1 !~ /---$/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following command:

Note: Replace <file_name> for the name of the file that was returned.

If the file was found in /bin or /lib, execute the following command:

chmod 700 <file_name>

If the file was found in /conf, execute the following command:

chmod 600 <file_name>

Repeat the command for each file that was returned.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44943r683861_chk'
  tag severity: 'high'
  tag gid: 'V-241667'
  tag rid: 'SV-241667r879631_rule'
  tag stig_id: 'VROM-TC-000520'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-44902r683862_fix'
  tag 'documentable'
  tag legacy: ['SV-99619', 'V-88969']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
