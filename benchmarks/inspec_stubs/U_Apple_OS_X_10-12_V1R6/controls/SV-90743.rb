control 'SV-90743' do
  title 'The OS X system must be configured to disable the system preference pane for Internet Accounts.'
  desc "It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled.

The system preference panel's iCloud and Internet Accounts must be disabled.

"
  desc 'check', 'To check if "Internet Accounts" has been disabled, run the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep com.apple.preferences.internetaccounts

If nothing is returned, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76055'
  tag rid: 'SV-90743r1_rule'
  tag stig_id: 'AOSX-12-000521'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82693r1_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
