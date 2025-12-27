control 'SV-225167' do
  title 'The macOS system must be configured to disable AirDrop.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

AirDrop must be disabled.'
  desc 'check', 'Verify that AirDrop has been disabled by running the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowAirDrop

If the return is not, "allowAirDrop = 0", this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26866r621622_chk'
  tag severity: 'low'
  tag gid: 'V-225167'
  tag rid: 'SV-225167r610901_rule'
  tag stig_id: 'AOSX-15-002009'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26854r467670_fix'
  tag 'documentable'
  tag legacy: ['V-102751', 'SV-111713']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
