control 'SV-48037' do
  title 'Alternate operating systems must not be permitted on the same system.'
  desc 'Allowing other operating systems to run on a secure system may allow security to be circumvented.'
  desc 'check', 'Verify the local system boots directly into Windows.  

Open Control Panel.
Select "System".
Select the "Advanced System Settings" link.
Select the "Advanced" tab.
Click the Startup and Recovery "Settings" button.  

If the drop-down list box "Default operating system:" shows any operating system other than Windows 8, this is a finding.'
  desc 'fix', 'Ensure Windows 8 is the only operating system on a device.  Remove alternate operating systems.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44776r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1119'
  tag rid: 'SV-48037r1_rule'
  tag stig_id: 'WN08-GE-000008'
  tag gtitle: 'Booting into Multiple Operating Systems'
  tag fix_id: 'F-41175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
