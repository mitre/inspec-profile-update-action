control 'SV-246939' do
  title 'ONTAP must enforce access restrictions associated with changes to the device configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to device configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the device could potentially have significant effects on the overall security of the device.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to device components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Use "security login show -role admin" to see users with administrative privilege that allow device configuration. 

If ONTAP cannot enforce access restrictions associated with changes to the device configuration, this is a finding.'
  desc 'fix', 'Configure users with administrative privilege that allows device configuration with "security login create -user-or-group-name <user_name> -role admin".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50371r769147_chk'
  tag severity: 'medium'
  tag gid: 'V-246939'
  tag rid: 'SV-246939r769149_rule'
  tag stig_id: 'NAOT-CM-000001'
  tag gtitle: 'SRG-APP-000380-NDM-000304'
  tag fix_id: 'F-50325r769148_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
