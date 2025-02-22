control 'SV-223464' do
  title 'CA-ACF2 must be installed, functional, and properly configured.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Refer to the active tasks on the system. You can use IBM SDSF or the system Log.

If CA-ACF2 is active, this is not a finding.'
  desc 'fix', 'Assure that CA-ACF2 is active on the system.'
  impact 0.7
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25137r500524_chk'
  tag severity: 'high'
  tag gid: 'V-223464'
  tag rid: 'SV-223464r853528_rule'
  tag stig_id: 'ACF2-ES-000450'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-25125r500525_fix'
  tag 'documentable'
  tag legacy: ['V-97625', 'SV-106729']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
