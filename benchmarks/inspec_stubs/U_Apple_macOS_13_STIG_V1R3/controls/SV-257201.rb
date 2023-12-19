control 'SV-257201' do
  title 'The macOS system must be configured to disable Remote Apple Events.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems can provide a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

Remote Apple Events must be disabled.'
  desc 'check', 'Verify the macOS system is configured to disable Remote Apple Events with the following command:

/bin/launchctl print-disabled system | /usr/bin/grep com.apple.AEServer

"com.apple.AEServer" => disabled

If the results are not "com.apple.AEServer => disabled", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable Remote Apple Events with the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.AEServer

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60886r905234_chk'
  tag severity: 'medium'
  tag gid: 'V-257201'
  tag rid: 'SV-257201r905236_rule'
  tag stig_id: 'APPL-13-002022'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-60827r905235_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
