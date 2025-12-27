control 'SV-214925' do
  title 'The macOS system must be configured to disable AirDrop.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

AirDrop must be disabled.'
  desc 'check', 'To check if AirDrop has been disabled, run the following command:

sudo /usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableAirDrop

If the result is not "DisableAirDrop = 1", this is a finding.'
  desc 'fix', 'Disabling AirDrop is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.3
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16125r397347_chk'
  tag severity: 'low'
  tag gid: 'V-214925'
  tag rid: 'SV-214925r609363_rule'
  tag stig_id: 'AOSX-13-002050'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16123r397348_fix'
  tag 'documentable'
  tag legacy: ['V-81731', 'SV-96445']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
