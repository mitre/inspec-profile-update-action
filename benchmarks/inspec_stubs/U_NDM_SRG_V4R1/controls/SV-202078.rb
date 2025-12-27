control 'SV-202078' do
  title 'The network device must only allow authorized administrators to view or change the device configuration, system files, and other files stored either in the device or on removable media (such as a flash drive).'
  desc 'This requirement is intended to address the confidentiality and integrity of system information at rest (e.g., network device rule sets) when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

Files on the network device or on removable media used by the device must have their permissions set to allow read or write access to those accounts that are specifically authorized to access or change them.  Note that different administrative accounts or roles will have varying levels of access.

File permissions must be set so that only authorized administrators can read or change their contents.  Whenever files are written to removable media and the media removed from the device, the media must be handled appropriately for the classification and sensitivity of the data stored on the device.'
  desc 'check', 'List the contents of the network device’s local storage, including any drives supporting removable media (such as flash drives or CDs) and check the file permissions of all files on those drives.  If any files allow read or write access by accounts not specifically authorized access or by non-privileged accounts, this is a finding.'
  desc 'fix', 'Set the file permissions on files on the network device or on removable media used by the device so that only authorized administrators can read or change their contents.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2204r381854_chk'
  tag severity: 'high'
  tag gid: 'V-202078'
  tag rid: 'SV-202078r397744_rule'
  tag stig_id: 'SRG-APP-000231-NDM-000271'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-2205r381855_fix'
  tag 'documentable'
  tag legacy: ['SV-69417', 'V-55171']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
