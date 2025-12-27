control 'SV-241668' do
  title 'tc Server API web server application directories must not be accessible to anonymous user.'
  desc 'In order to properly monitor the changes to the web server and the hosted applications, logging must be enabled. Along with logging being enabled, each record must properly contain the changes made and the names of those who made the changes.

Allowing anonymous users the capability to change the web server or the hosted application will not generate proper log information that can then be used for forensic reporting in the case of a security issue. Allowing anonymous users to make changes will also grant change capabilities to anybody without forcing a user to authenticate before the changes can be made.'
  desc 'check', "At the command prompt, find any world accessible files by executing the following commands:

ls -alR /usr/lib/vmware-vcops/tomcat-enterprise/bin /usr/lib/vmware-vcops/tomcat-enterprise/conf | grep -E '^-' | awk '$1 !~ /---$/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following commands:

find /usr/lib/vmware-vcops/tomcat-enterprise/conf -type f -exec chmod o=--- {} \\;

find /usr/lib/vmware-vcops/tomcat-enterprise/bin -type f -exec chmod o=--- {} \\;'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44944r684177_chk'
  tag severity: 'high'
  tag gid: 'V-241668'
  tag rid: 'SV-241668r879631_rule'
  tag stig_id: 'VROM-TC-000525'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-44903r683865_fix'
  tag 'documentable'
  tag legacy: ['SV-99621', 'V-88971']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
