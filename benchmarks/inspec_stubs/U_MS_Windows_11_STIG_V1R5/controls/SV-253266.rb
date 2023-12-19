control 'SV-253266' do
  title 'Alternate operating systems must not be permitted on the same system.'
  desc 'Allowing other operating systems to run on a secure system may allow security to be circumvented.'
  desc 'check', 'Verify the system does not include other operating system installations.

Run "Advanced System Settings".
Select the "Advanced" tab.
Click the "Settings" button in the "Startup and Recovery" section.

If the drop-down list box "Default operating system:" shows any operating system other than Windows 11, this is a finding.'
  desc 'fix', 'Ensure Windows 11 is the only operating system on a device. Remove alternate operating systems.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56719r828880_chk'
  tag severity: 'medium'
  tag gid: 'V-253266'
  tag rid: 'SV-253266r828882_rule'
  tag stig_id: 'WN11-00-000055'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56669r828881_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
