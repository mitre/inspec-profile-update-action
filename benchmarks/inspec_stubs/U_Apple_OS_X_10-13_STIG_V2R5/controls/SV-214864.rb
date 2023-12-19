control 'SV-214864' do
  title 'The macOS system must be configured to disable the UUCP service.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The system must not have the UUCP service active.'
  desc 'check', 'To check if the UUCP service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.uucp

If the results do not show the following, this is a finding:

"com.apple.uucp" => true'
  desc 'fix', 'To disable the UUCP service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.uucp

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16064r397164_chk'
  tag severity: 'medium'
  tag gid: 'V-214864'
  tag rid: 'SV-214864r609363_rule'
  tag stig_id: 'AOSX-13-000550'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16062r397165_fix'
  tag 'documentable'
  tag legacy: ['V-81607', 'SV-96321']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
