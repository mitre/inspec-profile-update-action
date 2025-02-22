control 'SV-223824' do
  title 'The IBM RACF SERVAUTH resource class must be active for TCP/IP resources.'
  desc 'IBM Provides the SERVAUTH Class for use in protecting a variety of TCP/IP features/functions/products both IBM and third-party. Failure to activate this class will result in unprotected resources. This exposure may threaten the integrity of the operating system environment, and compromise the confidentiality of customer data.'
  desc 'check', 'From a command input screen enter:
SETROPTS LIST

If there are TCP/IP resources defined and the SERVAUTH resource class is not active, this is a finding.'
  desc 'fix', 'Configure RACF SETROPTS to have the SERVAUTH resource class is active.

Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified in the example below: 

The RACF Command SETR LIST will show the status of RACF Controls including a list of ACTIVE classes. 

The SERVAUTH Class is activated with the command SETR CLASSACT (SERVAUTH).

Generic profiles and commands should also be enabled with the command SETR GENERIC(SERVAUTH) GENCMD(SERVAUTH).'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25497r515160_chk'
  tag severity: 'medium'
  tag gid: 'V-223824'
  tag rid: 'SV-223824r604139_rule'
  tag stig_id: 'RACF-TC-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25485r515161_fix'
  tag 'documentable'
  tag legacy: ['V-98355', 'SV-107459']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
