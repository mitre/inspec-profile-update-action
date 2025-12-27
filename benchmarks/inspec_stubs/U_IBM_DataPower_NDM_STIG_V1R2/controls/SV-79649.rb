control 'SV-79649' do
  title 'The DataPower Gateway must enforce access restrictions associated with changes to device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the device can potentially have significant effects on the overall security of the device. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to device components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'In the DataPower web interface, navigate to Administration >> Access. Check User Account, User Group, and RBM settings to ensure that appropriate access restrictions are in place

If the User Account, User Group, and RBM settings have not been configured, this is a finding.'
  desc 'fix', "Configure DataPower Gateway to restrict actions associated with device configuration. This is defined and enforced through group and user access privileges as well as DataPower's Role-based management settings.

Configure these settings using the DataPower WebGUI at Administration >> Access."
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65787r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65159'
  tag rid: 'SV-79649r1_rule'
  tag stig_id: 'WSDP-NM-000106'
  tag gtitle: 'SRG-APP-000380-NDM-000304'
  tag fix_id: 'F-71099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
