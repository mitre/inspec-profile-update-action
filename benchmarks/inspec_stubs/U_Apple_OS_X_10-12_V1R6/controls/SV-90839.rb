control 'SV-90839' do
  title 'The OS X system must be configured to disable Internet Sharing.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Internet Sharing must be disabled.'
  desc 'check', 'To check if Internet Sharing is disabled, use the following command:

/usr/bin/sudo /bin/launchctl print-disabled system | /usr/bin/grep com.apple.NetworkSharing

If the results do not show the following, this is a finding:

"com.apple.NetworkSharing" => true'
  desc 'fix', 'To disable Internet Sharing, run the following command:

/usr/bin/sudo /bin/launchctl disable system/com.apple.NetworkSharing

The system may need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76151'
  tag rid: 'SV-90839r1_rule'
  tag stig_id: 'AOSX-12-001270'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82789r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
