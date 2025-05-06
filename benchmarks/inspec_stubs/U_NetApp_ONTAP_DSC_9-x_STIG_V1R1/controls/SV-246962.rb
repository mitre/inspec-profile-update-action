control 'SV-246962' do
  title 'ONTAP must allow only authorized administrators to view or change the device configuration, system files, and other files stored either in the device or on removable media (such as a flash drive).'
  desc 'This requirement is intended to address the confidentiality and integrity of system information at rest (e.g., network device rule sets) when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

Files on the network device or on removable media used by the device must have their permissions set to allow read or write access to those accounts that are specifically authorized to access or change them. Note that different administrative accounts or roles will have varying levels of access.

File permissions must be set so that only authorized administrators can read or change their contents. Whenever files are written to removable media and the media removed from the device, the media must be handled appropriately for the classification and sensitivity of the data stored on the device.'
  desc 'check', 'Use "security login show" to see all configured users and their roles.

Use "security login role show -role admin" to see ONTAP administrator accounts with privileged access.

If ONTAP cannot be configured to only allow authorized administrators to view or change the device configuration, system files, and other files stored either in the device or on removable media (such as a flash drive), this is a finding.'
  desc 'fix', 'Configure administrator accounts with privileged access with "security login create -user-or-group-name <user_name> -role admin".'
  impact 0.7
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50394r769216_chk'
  tag severity: 'high'
  tag gid: 'V-246962'
  tag rid: 'SV-246962r769218_rule'
  tag stig_id: 'NAOT-SC-000004'
  tag gtitle: 'SRG-APP-000231-NDM-000271'
  tag fix_id: 'F-50348r769217_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
