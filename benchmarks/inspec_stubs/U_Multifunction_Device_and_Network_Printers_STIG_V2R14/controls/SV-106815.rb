control 'SV-106815' do
  title 'The MFD must be configured to prohibit the use of all unnecessary and/or nonsecure functions, physical and logical ports, protocols, and/or services.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable unused or unnecessary physical and logical ports/protocols on information systems.

MFDs are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. 

To support the requirements and principles of least functionality, the MFD must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved. Some network devices have capabilities enabled by default; if these capabilities are not necessary, they must be disabled. If a particular capability is used, then it must be documented and approved.'
  desc 'check', 'Determine if the network device prohibits the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services. This includes hardware ports such as USB ports. 

If any unnecessary or nonsecure functions, ports, protocols and/or services are permitted, this is a finding.'
  desc 'fix', 'Configure the MFD to prohibit the use of all unnecessary and/or nonsecure functions, ports, protocols, and/or services. This included hardware ports, for example USB ports.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-96545r1_chk'
  tag severity: 'medium'
  tag gid: 'V-97711'
  tag rid: 'SV-106815r1_rule'
  tag stig_id: 'MFD03.002'
  tag gtitle: 'MFD03.002'
  tag fix_id: 'F-103387r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
