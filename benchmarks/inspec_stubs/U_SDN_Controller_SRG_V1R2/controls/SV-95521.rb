control 'SV-95521' do
  title 'The SDN controller must be configured to enforce access restrictions associated with changes to the configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to restrict access to the configuration. 

If the SDN controller is not configured to enforce access restrictions associated with changes to the configuration, this is a finding.'
  desc 'fix', 'Configure the SDN controller to restrict access to the configuration.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80547r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80811'
  tag rid: 'SV-95521r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001095'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87665r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
