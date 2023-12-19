control 'SV-230789' do
  title 'The macOS system must be configured to disable Location Services.'
  desc 'To prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality-of-life issues.

Location Services must be disabled.'
  desc 'check', 'If Location Services are authorized by the Authorizing Official, this is Not Applicable.

Verify that Location Services are disabled:

The setting is found in System Preferences >> Security & Privacy >> Privacy >> Location Services.

If the box that says, "Enable Location Services" is checked, this is a finding.'
  desc 'fix', 'Disable the Location Services:

The setting is found in System Preferences >> Security & Privacy >> Privacy >> Location Services.

Uncheck the box labeled "Enable Location Services".'
  impact 0.5
  ref 'DPMS Target Apple macOS 11'
  tag check_id: 'C-33734r607254_chk'
  tag severity: 'medium'
  tag gid: 'V-230789'
  tag rid: 'SV-230789r599842_rule'
  tag stig_id: 'APPL-11-002004'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-33707r607255_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
