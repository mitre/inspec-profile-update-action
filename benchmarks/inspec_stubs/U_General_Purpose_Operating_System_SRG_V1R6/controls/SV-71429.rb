control 'SV-71429' do
  title 'The operating system must enforce access restrictions.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the operating system can have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to operating system components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Verify the operating system enforces access restrictions. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce access restrictions.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57739r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57169'
  tag rid: 'SV-71429r1_rule'
  tag stig_id: 'SRG-OS-000364-GPOS-00151'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-62065r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
