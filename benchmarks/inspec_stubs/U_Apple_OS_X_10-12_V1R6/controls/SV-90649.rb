control 'SV-90649' do
  title 'The OS X system must be configured to disable rshd service.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The "rshd" service must be disabled.'
  desc 'check', 'To check if the "rshd" service is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.rshd

If the results do not show the following, this is a finding:

"com.apple.rshd" => true'
  desc 'fix', 'To disable the "rshd" service, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.rshd

The system may need to be restarted for the update to take effect.'
  impact 0.7
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75645r1_chk'
  tag severity: 'high'
  tag gid: 'V-75961'
  tag rid: 'SV-90649r1_rule'
  tag stig_id: 'AOSX-12-000050'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82599r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
