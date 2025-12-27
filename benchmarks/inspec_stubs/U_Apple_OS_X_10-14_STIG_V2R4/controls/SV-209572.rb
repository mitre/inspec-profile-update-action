control 'SV-209572' do
  title 'The macOS system must be configured to disable Internet Sharing.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

Internet Sharing is non-essential and must be disabled.'
  desc 'check', 'To check if Internet Sharing is disabled, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep forceInternetSharingOff

If the return is not, "forceInternetSharingOff = 1", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9823r282198_chk'
  tag severity: 'medium'
  tag gid: 'V-209572'
  tag rid: 'SV-209572r610285_rule'
  tag stig_id: 'AOSX-14-002007'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-9823r282199_fix'
  tag 'documentable'
  tag legacy: ['SV-105015', 'V-95877']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
