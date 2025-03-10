control 'SV-257190' do
  title 'The macOS system must be configured to disable Internet Sharing.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems can provide a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

Internet Sharing is nonessential and must be disabled.'
  desc 'check', 'Verify the macOS system is configured to disable Internet Sharing with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "forceInternetSharingOff"

forceInternetSharingOff = 1;

If there is no result, or if "forceInternetSharingOff" is not set to "1", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable Internet Sharing by installing the "Custom Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60875r905201_chk'
  tag severity: 'medium'
  tag gid: 'V-257190'
  tag rid: 'SV-257190r905203_rule'
  tag stig_id: 'APPL-13-002007'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60816r905202_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
