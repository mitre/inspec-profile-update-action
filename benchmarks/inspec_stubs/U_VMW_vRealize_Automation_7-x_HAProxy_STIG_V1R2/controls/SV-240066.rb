control 'SV-240066' do
  title 'HAProxy must prohibit anonymous users from editing system files.'
  desc 'Allowing anonymous users the capability to change the web server or the hosted application will not generate proper log information that can then be used for forensic reporting in the case of a security issue. Allowing anonymous users to make changes will also grant change capabilities to anybody without forcing a user to authenticate before the changes can be made.'
  desc 'check', "At the command prompt, execute the following command:

ls -alR /etc/haproxy /var/lib/haproxy /usr/sbin/haproxy | grep -E '^-' | awk '{print $1}' | cut -c9 | grep w

If the command returns any value, this is a finding."
  desc 'fix', 'Navigate to and remove anonymous permissions for any listed files.'
  impact 0.7
  ref 'DPMS Target VMware vRealize Automation 7-x HA Proxy'
  tag check_id: 'C-43299r665365_chk'
  tag severity: 'high'
  tag gid: 'V-240066'
  tag rid: 'SV-240066r879631_rule'
  tag stig_id: 'VRAU-HA-000225'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-43258r665366_fix'
  tag 'documentable'
  tag legacy: ['SV-99819', 'V-89169']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
