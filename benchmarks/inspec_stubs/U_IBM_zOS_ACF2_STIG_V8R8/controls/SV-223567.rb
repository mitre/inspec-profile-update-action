control 'SV-223567' do
  title 'IBM z/OS must properly configure CONSOLxx members.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.

MCS consoles can be used to issue operator commands. Failure to properly control access to MCS consoles could result in unauthorized personnel issuing sensitive operator commands. This exposure may threaten the integrity and availability of the operating system environment, and compromise the confidentiality of customer data.'
  desc 'check', 'Review each CONSOLxx parmlib member. 

If the following guidance is true, this is not a finding. 

The "DEFAULT" statement for each CONSOLxx member specifies "LOGON(REQUIRED)" or "LOGON(AUTO)".

The "CONSOLE" statement for each console assigns a unique name using the "NAME" parameter.

The "CONSOLE" statement for each console specifies "AUTH(INFO)". Exceptions are the "AUTH" parameter is not valid for consoles defined with "UNIT(PRT)" and specifying "AUTH(MASTER)" is permissible for the system console.

Note: The site should be able to determine the system consoles. However, it is imperative that the site adhere to the "DEFAULT" statement requirement.'
  desc 'fix', 'Configure the "DEFAULT" statement to specify "LOGON(REQUIRED)" so that all operators are required to log on prior to entering z/OS system commands. At the discretion of the ISSO, "LOGON(AUTO)" may be used. If "LOGON(AUTO)" is used assure that the console userids are defined with minimal access. 

Configure each "CONSOLE" statement to specify an explicit console NAME. And that "AUTH(INFO)" is specified, this also including extended MCS consoles. "AUTH(MASTER)" may be specified for systems console.

Note: The site should be able to determine the system consoles. However, it is imperative that the site adhere to the "DEFAULT" statement requirement.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25240r504722_chk'
  tag severity: 'medium'
  tag gid: 'V-223567'
  tag rid: 'SV-223567r533198_rule'
  tag stig_id: 'ACF2-OS-000320'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25228r504723_fix'
  tag 'documentable'
  tag legacy: ['SV-106943', 'V-97839']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
