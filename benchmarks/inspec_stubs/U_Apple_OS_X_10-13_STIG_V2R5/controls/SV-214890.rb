control 'SV-214890' do
  title 'The macOS system must implement cryptographic mechanisms to protect the confidentiality and integrity of all information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive) within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. By encrypting the system hard drive, the confidentiality and integrity of any data stored on the system is ensured. FileVault Disk Encryption mitigates this risk.

'
  desc 'check', 'To check if "FileVault 2" is enabled, run the following command:

/usr/bin/sudo /usr/bin/fdesetup status

If "FileVault" is "Off" and the device is a mobile device or the organization has determined that the drive must encrypt data at rest, this is a finding.'
  desc 'fix', 'Open System Preferences >> Security and Privacy and navigate to the "FileVault" tab. Use this panel to configure full-disk encryption.

Alternately, from the command line, run the following command to enable "FileVault":

/usr/bin/sudo /usr/bin/fdesetup enable

After "FileVault" is initially set up, additional users can be added.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16090r397242_chk'
  tag severity: 'medium'
  tag gid: 'V-214890'
  tag rid: 'SV-214890r609363_rule'
  tag stig_id: 'AOSX-13-000780'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-16088r397243_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag 'documentable'
  tag legacy: ['SV-96373', 'V-81659']
  tag cci: ['CCI-002475', 'CCI-002476', 'CCI-001199']
  tag nist: ['SC-28 (1)', 'SC-28 (1)', 'SC-28']
end
