control 'SV-257204' do
  title 'The macOS system must be configured to disable the Cloud Setup services.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems can provide a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

Examples of nonessential capabilities include, but are not limited to, games, software packages, tools, and demonstration software, not related to requirements or providing a wide array of functionality not required for every mission, but which cannot be disabled.'
  desc 'check', 'Verify the macOS system is configured to disable the Cloud Setup services with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "SkipCloudSetup"

SkipCloudSetup = 1;

If there is no result, or if "SkipCloudSetup" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the Cloud Setup services by installing the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60889r905243_chk'
  tag severity: 'medium'
  tag gid: 'V-257204'
  tag rid: 'SV-257204r905245_rule'
  tag stig_id: 'APPL-13-002035'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60830r905244_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
