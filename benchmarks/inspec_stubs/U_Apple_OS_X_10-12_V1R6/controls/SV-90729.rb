control 'SV-90729' do
  title 'The OS X system must be configured to disable the iCloud Calendar services.'
  desc "It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The application Calendar establishes connections to Apple's iCloud, despite using security controls to disable iCloud access.

"
  desc 'check', 'To check if there is a configuration policy defined for "Application Restrictions", run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "familyControlsEnabled = 1;"

If nothing is returned, this is a finding.

To check if iCloudCalendar is disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowCloudCalendar = 0;"

If nothing is returned, this is a finding.

Built-in applications such as iCloud Calendar should be evaluated against mission needs and should only appear in the list of allowed applications if specifically required.'
  desc 'fix', 'This setting is enforced using the "Applications Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75725r1_chk'
  tag severity: 'low'
  tag gid: 'V-76041'
  tag rid: 'SV-90729r1_rule'
  tag stig_id: 'AOSX-12-000505'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82679r1_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
