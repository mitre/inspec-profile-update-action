control 'SV-234216' do
  title 'The FortiGate device must only allow authorized administrators to view or change the device configuration, system files, and other files stored either in the device or on removable media (such as a flash drive).'
  desc 'This requirement is intended to address the confidentiality and integrity of system information at rest (e.g., network device rule sets) when it is located on a storage device within the network device or as a component of the network device. This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

Files on the network device or on removable media used by the device must have their permissions set to allow read or write access to those accounts that are specifically authorized to access or change them. Note that different administrative accounts or roles will have varying levels of access.

File permissions must be set so that only authorized administrators can read or change their contents. Whenever files are written to removable media and the media removed from the device, the media must be handled appropriately for the classification and sensitivity of the data stored on the device.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click Administrators.
3. Click each administrator and hover over the profile that is assigned to the role.
4. Click Edit.
5. Verify that the permission on System is set to READ or Read/Write.

If any unauthorized administrator has Read/Write access to System, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command for all low privileged admin users:

     # show system admin  {ADMIN NAME}  | grep -i accprofile
The output should be:  
           set accprofile {PROFILE NAME}

Use the profile name from the output result of above command. 
     # show system accprofile {PROFILE NAME} | grep -i sysgrp
The output should be:  
          set sysgrp none
          
If any low privileged admin user has sysgrp parameter set to values other than NONE, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. First edit the admin profile by running the following command:

     # config system accprofile 
           # edit {PROFILE NAME}
                 # set sysgrp read-write
          # next
     # end
Then, assign appropriate admin profiles to the administrator account. 
     # config system admin  
          # edit {ADMIN NAME}
          # set accprofile  {PROFILE NAME}
          # next
     # end

This profile should only be assigned to administrators authorized to change system configurations.'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37401r611835_chk'
  tag severity: 'high'
  tag gid: 'V-234216'
  tag rid: 'SV-234216r628777_rule'
  tag stig_id: 'FGFW-ND-000285'
  tag gtitle: 'SRG-APP-000231-NDM-000271'
  tag fix_id: 'F-37366r611836_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
