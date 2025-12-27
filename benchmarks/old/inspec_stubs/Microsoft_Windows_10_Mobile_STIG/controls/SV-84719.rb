control 'SV-84719' do
  title 'Windows 10 Mobile must protect data at rest on removable storage media.'
  desc "The MOS must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #26"
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if data in the mobile device's removable storage media is encrypted. If feasible, use a spare device to confirm that data-at-rest protection is enabled for removable storage media.

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to verify the phone compliance policy.
2. Find the setting for "require storage cards to be encrypted".
3. Verify the setting for requiring require storage card encryption is enforced.

On a Windows 10 Mobile device that contains a microSD slot and has a microSD card inserted:

1. Launch "Settings".
2. Tap on "Update & security" and then tap on "Device encryption".
3. Under the section called "Device encryption" there are two settings, the first one is for enforcing encryption on main device storage and the second which controls encryption of removable storage cards like SD cards.   For this control examine the second setting for SD cards.
4. Verify that the device encryption for SD cards setting is toggled to "On".

If the MDM does not have a policy enforcement that enforces the encryption of removable storage (SD) cards, this is a finding.)
  desc 'fix', 'Configure the MDM system to enforce a policy which configures the "require storage cards to be encrypted" policy to be enabled for Windows 10 Mobile devices. 

Deploy the MDM policy to managed devices.'
  impact 0.7
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70573r2_chk'
  tag severity: 'high'
  tag gid: 'V-70097'
  tag rid: 'SV-84719r2_rule'
  tag stig_id: 'MSWM-10-201705'
  tag gtitle: 'PP-MDF-201012'
  tag fix_id: 'F-76333r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
