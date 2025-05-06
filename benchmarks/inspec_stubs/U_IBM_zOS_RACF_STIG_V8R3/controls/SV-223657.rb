control 'SV-223657' do
  title 'The IBM RACF FACILITY resource class must be active.'
  desc 'IBM Provides the FACILITY Class for use in protecting a variety of features/functions/products both IBM and third-party. The FACILITY Class is not dedicated to any one specific use and is intended as a multi-purpose RACF Class. Failure to activate this class will result in unprotected resources. This exposure may threaten the integrity of the operating system environment, and compromise the confidentiality of customer data.'
  desc 'check', 'The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

From the ISPF Command Shell enter:
SETRopts List

If the FACILITY resource class is active, this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below:

The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

The FACILITY Class is activated with the command SETR CLASSACT(FACILITY).

Generic profiles and commands should also be enabled with the command SETR GENERIC(FACILITY) GENCMD(FACILITY).

IBM recommends RACLISTing the FACILITY Class which is accomplished with the command SETR RACL(FACILITY).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25330r514660_chk'
  tag severity: 'medium'
  tag gid: 'V-223657'
  tag rid: 'SV-223657r604139_rule'
  tag stig_id: 'RACF-ES-000090'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25318r514661_fix'
  tag 'documentable'
  tag legacy: ['V-98019', 'SV-107123']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
