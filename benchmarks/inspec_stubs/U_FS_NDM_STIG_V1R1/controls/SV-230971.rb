control 'SV-230971' do
  title 'Forescout must only allow authorized administrators to view or change the device configuration, system files, and other files stored either in the device or on removable media (such as a flash drive).'
  desc 'This requirement addresses the confidentiality and integrity of system information at rest (e.g., network device rule sets) when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

Files on the network device or on removable media used by the device must have their permissions set to allow read or write access to those accounts specifically authorized to access or change them. Note that different administrative accounts or roles will have varying levels of access.

File permissions must be set so that only authorized administrators can read or change their contents. Whenever files are written to removable media and the media removed from the device, the media must be handled appropriately for the classification and sensitivity of the data stored on the device.'
  desc 'check', 'List the contents of Forescout’s local storage, including any drives supporting removable media (such as flash drives), and check the file permissions of all files on those drives.

1. Review accounts with incorrect update privileges to Forescout appliance configuration by selecting Tools >> Options >> CounterACT User Profiles.
2. Select a user to edit.
3. Select the "Permissions" tab.
4. Verify the "CounterAct Appliance Configuration" and "CounterACT Appliance Control" radio buttons are set to "View only".

If any files allow read or write access by accounts not specifically authorized access or access using non-privileged accounts, this is a finding.'
  desc 'fix', 'Review the SSP or other documentation for a list of user accounts and privileges. Set the file permissions on files on Forescout or on removable media used by the device so that only authorized administrators can read or change their contents. This is completed by limiting access to SUDO accounts and command line admin accounts.

1. Review accounts with incorrect update privileges to Forescout appliance configuration by selecting Tools >> Options >> CounterACT User Profiles.
2. Select a user to edit.
3. Select the "Permissions" tab.
4. Ensure the "CounterACT Appliance Configuration" and "CounterACT Appliance Control" radio buttons are set to "View only".'
  impact 0.7
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33901r603752_chk'
  tag severity: 'high'
  tag gid: 'V-230971'
  tag rid: 'SV-230971r615886_rule'
  tag stig_id: 'FORE-NM-000450'
  tag gtitle: 'SRG-APP-000231-NDM-000271'
  tag fix_id: 'F-33874r603753_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
