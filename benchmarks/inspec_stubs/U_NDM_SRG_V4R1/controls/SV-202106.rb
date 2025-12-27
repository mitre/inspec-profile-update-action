control 'SV-202106' do
  title 'The network device must enforce access restrictions associated with changes to device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the device can potentially have significant effects on the overall security of the device. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to device components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Determine if the network device enforces access restrictions associated with changes to device configuration.

If the network device does not enforce such access restrictions, this is a finding.'
  desc 'fix', 'Configure the network device to enforce access restrictions associated with changes to device configuration.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2232r381947_chk'
  tag severity: 'medium'
  tag gid: 'V-202106'
  tag rid: 'SV-202106r400006_rule'
  tag stig_id: 'SRG-APP-000380-NDM-000304'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-2233r381948_fix'
  tag 'documentable'
  tag legacy: ['SV-69489', 'V-55243']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
