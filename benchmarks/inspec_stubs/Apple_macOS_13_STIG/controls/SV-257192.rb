control 'SV-257192' do
  title 'The macOS system must be configured to disable AirDrop.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems can provide a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

AirDrop must be disabled.

Note: There is a known bug in the graphical user interface where the user can toggle AirDrop in the UI, which indicates the service has been turned on, but it remains disabled if the Restrictions Profile has been applied.'
  desc 'check', 'Verify the macOS system is configured to disable AirDrop with the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowAirDrop"

allowAirDrop = 0;

If there is no result, or if "allowAirDrop" is not set to "0", this is a finding.'
  desc 'fix', 'Configure the macOS system to disable AirDrop by installing the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60877r905207_chk'
  tag severity: 'low'
  tag gid: 'V-257192'
  tag rid: 'SV-257192r905209_rule'
  tag stig_id: 'APPL-13-002009'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60818r905208_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
