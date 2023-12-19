control 'SV-257249' do
  title 'The macOS system must be configured to prevent activity continuation between Apple devices.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems can provide a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify the macOS system is configured to prevent activity continuation between Apple devices with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowActivityContinuation"

allowActivityContinuation = 0;

If "allowActivityContinuation" is not set to "0", this is a finding.'
  desc 'fix', 'Configure the macOS system to prevent activity continuation between Apple devices by installing the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60934r905378_chk'
  tag severity: 'low'
  tag gid: 'V-257249'
  tag rid: 'SV-257249r905380_rule'
  tag stig_id: 'APPL-13-005058'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60875r905379_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
