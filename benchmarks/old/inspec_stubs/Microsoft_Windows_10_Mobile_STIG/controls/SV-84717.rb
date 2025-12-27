control 'SV-84717' do
  title 'Windows 10 Mobile must protect data at rest on built-in storage media.'
  desc "The MOS must ensure the data being written to the mobile device's built-in storage media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read storage media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #25"
  desc 'check', %q(Review Windows 10 Mobile configuration settings to determine if data in the mobile device's built-in storage media is encrypted. 

This validation procedure is performed on both the MDM administration console and the Windows 10 Mobile device.

On the MDM administration console:

1. Ask the MDM administrator to display the device encryption setting.
2. Verify device encryption is activated.

On the Windows 10 Mobile device:

1. Launch "Settings".
2. Select "Update & security".
3. Select "Device encryption".
4. Verify the toggle for Device Encryption is set to "On" and that setting is disabled/read-only.

If the MDM is not configured to enforce encryption, or if the "Device encryption" setting is not toggled to "On" and disabled/read-only, this is a finding.)
  desc 'fix', 'Configure the MDM system to require device encryption for Windows 10 Mobile devices. 

Deploy the MDM policy to managed devices.'
  impact 0.7
  ref 'DPMS Target Windows 10 Mobile'
  tag check_id: 'C-70571r1_chk'
  tag severity: 'high'
  tag gid: 'V-70095'
  tag rid: 'SV-84717r1_rule'
  tag stig_id: 'MSWM-10-201405'
  tag gtitle: 'PP-MDF-201011'
  tag fix_id: 'F-76331r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
