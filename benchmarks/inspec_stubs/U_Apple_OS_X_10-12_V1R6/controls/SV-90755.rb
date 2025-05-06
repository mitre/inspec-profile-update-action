control 'SV-90755' do
  title 'The OS X system must be configured to disable Bonjour multicast advertising.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

Bonjour multicast advertising must be disabled on the system.'
  desc 'check', 'To check if Bonjour multicast advertising has been disabled, run the following command:

/usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.mDNSResponder | /usr/bin/grep NoMulticastAdvertisements

If an error is returned, nothing is returned, or "NoMulticastAdvertisements" is not set to "1", this is a finding.'
  desc 'fix', 'To configure Bonjour to disable multicast advertising, run the following command:

/usr/bin/sudo /usr/bin/defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool true

The system will need to be restarted for the update to take effect.'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75751r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76067'
  tag rid: 'SV-90755r1_rule'
  tag stig_id: 'AOSX-12-000545'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-82705r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
