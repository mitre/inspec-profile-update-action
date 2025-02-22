control 'SV-207470' do
  title 'The VMM must enforce access restrictions associated with changes to the system.'
  desc 'Failure to provide logical access restrictions associated with changes to system configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the VMM can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to VMM components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to guest VMs, workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into VMMs), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Verify the VMM enforces access restrictions associated with changes to the system.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to enforce access restrictions associated with changes to the system.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7727r365814_chk'
  tag severity: 'medium'
  tag gid: 'V-207470'
  tag rid: 'SV-207470r854643_rule'
  tag stig_id: 'SRG-OS-000364-VMM-001410'
  tag gtitle: 'SRG-OS-000364'
  tag fix_id: 'F-7727r365815_fix'
  tag 'documentable'
  tag legacy: ['V-57141', 'SV-71401']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
