control 'SV-90917' do
  title 'CounterACT must allow only authorized administrators to view or change the device configuration, system files, and other files stored either in the device or on removable media.'
  desc 'This protection is required to prevent unauthorized alteration, corruption, or disclosure of information when not stored directly on the network device.

Files on the network device or on removable media used by the device must have their permissions set to allow read or write access to those accounts that are specifically authorized to access or change them. Note that different administrative accounts or roles will have varying levels of access.

File permissions must be set so that only authorized administrators can read or change their contents. Whenever files are written to removable media and the media is removed from the device, the media must be handled appropriately for the classification and sensitivity of the data stored on the device.

Flash drive usage must comply with DoD external storage and flash drive policy which includes permission to use and malware verification processes.'
  desc 'check', 'List the contents of CounterACT’s local storage, including any drives supporting removable media (such as flash drives), and check the file permissions of all files on those drives.

1. Log on to the SSH command line interface of a CounterACT Enterprise Manager (EM) or CounterACT appliance using standard admin privilege.
2. At the command prompt, type:
cd /
(To narrow the search to a specific LINUX directory, replace the / with the full pathname of the directory to be searched.)
3. Use the following command to review file permissions:
ls- la

If any files allow read or write access by accounts not specifically authorized access or access using non-privileged accounts, this is a finding.'
  desc 'fix', 'Set the file permissions on files on CounterACT or on removable media used by the device so that only authorized administrators can read or change their contents. This is completed by limiting access to SUDO accounts and command line admin accounts.

1. Review accounts with update privileges to CounterACT appliance configuration by selecting Tools >> Options >> Console User Profiles.
2. Select a user to edit.
3. Select the "Permissions" tab.
4. Ensure the "CounterACT Appliance Configuration" and "CounterACT Appliance Control" radio buttons are set to "View only".'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76229'
  tag rid: 'SV-90917r1_rule'
  tag stig_id: 'CACT-NM-000003'
  tag gtitle: 'SRG-APP-000231-NDM-000271'
  tag fix_id: 'F-82865r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
