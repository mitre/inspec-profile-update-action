control 'SV-257241' do
  title 'The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive) within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be lost or stolen, and the contents of their data storage (e.g., hard drives and nonvolatile memory) can be read, copied, or altered. By encrypting the system hard drive, the confidentiality and integrity of any data stored on the system is ensured. FileVault Disk Encryption mitigates this risk.

'
  desc 'check', 'Verify the macOS system is configured to enable "FileVault" with the following command:

/usr/bin/fdesetup status

If "FileVault" is "Off" and the device is a mobile device or the organization has determined that the drive must encrypt data at rest, this is a finding.'
  desc 'fix', 'Configure the macOS system to enable "FileVault" by opening System Settings >> Privacy & Security >> Security and navigate to the "FileVault" section. Use this panel to configure full-disk encryption.

Alternatively, from the command line, run the following command to enable "FileVault":

/usr/bin/sudo /usr/bin/fdesetup enable

After "FileVault" is initially set up, additional users can be added.'
  impact 0.7
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60926r905354_chk'
  tag severity: 'high'
  tag gid: 'V-257241'
  tag rid: 'SV-257241r905356_rule'
  tag stig_id: 'APPL-13-005020'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-60867r905355_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
