control 'SV-234523' do
  title 'The UEM server must enforce access restrictions associated with changes to the server configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover). 

Satisfies:FMT_SMR.1.1(1)'
  desc 'check', 'Verify the UEM server enforces access restrictions associated with changes to the server configuration.

If the UEM server does not enforce access restrictions associated with changes to the server configuration, this is a finding.'
  desc 'fix', 'Configure the UEM server to enforce access restrictions associated with changes to the server configuration.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37708r615212_chk'
  tag severity: 'medium'
  tag gid: 'V-234523'
  tag rid: 'SV-234523r879753_rule'
  tag stig_id: 'SRG-APP-000380-UEM-000251'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-37673r615213_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
