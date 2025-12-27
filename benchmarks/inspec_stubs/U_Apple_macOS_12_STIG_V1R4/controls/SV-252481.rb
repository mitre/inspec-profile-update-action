control 'SV-252481' do
  title 'The macOS system must be configured to disable Location Services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

Location Services must be disabled.'
  desc 'check', "If Location Services are authorized by the Authorizing Official, this is Not Applicable.

Verify that Location Services are disabled:
/usr/bin/sudo /usr/bin/defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd | egrep 'LocationServicesEnabled'

LocationServicesEnabled = 0

If 'LocationServicesEnabled' is not set to '0', this is a finding."
  desc 'fix', 'Disable the Location Services by running the following command: 

/usr/bin/sudo /usr/bin/defaults write /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled -bool false'
  impact 0.5
  ref 'DPMS Target Apple macOS 12'
  tag check_id: 'C-55937r816255_chk'
  tag severity: 'medium'
  tag gid: 'V-252481'
  tag rid: 'SV-252481r816257_rule'
  tag stig_id: 'APPL-12-002004'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-55887r816256_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
