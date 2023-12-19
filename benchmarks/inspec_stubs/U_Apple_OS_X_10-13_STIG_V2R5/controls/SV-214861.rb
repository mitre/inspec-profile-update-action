control 'SV-214861' do
  title 'The macOS system must be configured to disable the iCloud Find My Mac service.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

Find My Mac must be disabled.

'
  desc 'check', 'To check if Find My Mac is disabled, use the following command:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCloudFMM

If the return is null or not “allowCloudFMM = 0”, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16061r397155_chk'
  tag severity: 'medium'
  tag gid: 'V-214861'
  tag rid: 'SV-214861r609363_rule'
  tag stig_id: 'AOSX-13-000531'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16059r397156_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['V-81601', 'SV-96315']
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
