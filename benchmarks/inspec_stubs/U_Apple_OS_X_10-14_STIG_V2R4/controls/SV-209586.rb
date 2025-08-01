control 'SV-209586' do
  title 'The macOS system must be configured to disable Remote Apple Events.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

Remote Apple Events must be disabled.'
  desc 'check', 'To check if Remote Apple Events is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.AEServer

If the results do not show the following, this is a finding.

"com.apple.AEServer" => true'
  desc 'fix', 'To disable Remote Apple Events, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.AEServer

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9837r282240_chk'
  tag severity: 'medium'
  tag gid: 'V-209586'
  tag rid: 'SV-209586r610285_rule'
  tag stig_id: 'AOSX-14-002022'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-9837r282241_fix'
  tag 'documentable'
  tag legacy: ['SV-105049', 'V-95911']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
