control 'SV-223702' do
  title 'IBM RACF SETROPTS RVARYPW values must be properly set.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'From the ISPF Command Shell enter:

SETROPTS LIST

If the "INSTALLATION DEFINED RVARY PASSWORD IS IN EFFECT" message for both the SWITCH and STATUS functions, this is not a finding.'
  desc 'fix', 'Configure RACF ensure that the RVARYPW passwords are specified and conform to password requirements documented in RACF0460. The ISSO will evaluate the impact associated with implementation of the control option and develop a plan of action to implement the control option as required.

A sample command for setting both the SWITCH and STATUS passwords are shown here:

SETR RVARYPW(SWITCH(Wxy$8Pqu) STATUS(pbZ0@wL2))'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25375r514794_chk'
  tag severity: 'medium'
  tag gid: 'V-223702'
  tag rid: 'SV-223702r853605_rule'
  tag stig_id: 'RACF-ES-000550'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-25363r514795_fix'
  tag 'documentable'
  tag legacy: ['V-98111', 'SV-107215']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
