control 'SV-252544' do
  title 'The macOS system must be configured to prevent password proximity sharing requests from nearby Apple Devices.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of non-essential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'To check if allowPasswordProximityRequests is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowPasswordProximityRequests
  
If the return is not "allowPasswordProximityRequests = 0", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-56000r816444_chk'
  tag severity: 'medium'
  tag gid: 'V-252544'
  tag rid: 'SV-252544r816446_rule'
  tag stig_id: 'APPL-12-005060'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-55950r816445_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
