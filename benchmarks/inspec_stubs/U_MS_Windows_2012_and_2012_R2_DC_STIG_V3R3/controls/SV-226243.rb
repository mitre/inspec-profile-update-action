control 'SV-226243' do
  title 'The system must not boot into multiple operating systems (dual-boot).'
  desc 'Allowing a system to boot into multiple operating systems (dual-booting) may allow security to be circumvented on a secure system.'
  desc 'check', 'Verify the local system boots directly into Windows.  

Open Control Panel.
Select "System".
Select the "Advanced System Settings" link.
Select the "Advanced" tab.
Click the "Startup and Recovery" Settings button.  

If the drop-down list box "Default operating system:" shows any operating system other than Windows Server 2012, this is a finding.'
  desc 'fix', 'Ensure Windows Server 2012 is the only operating system installed for the system to boot into.  Remove alternate operating systems.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27945r476573_chk'
  tag severity: 'medium'
  tag gid: 'V-226243'
  tag rid: 'SV-226243r794576_rule'
  tag stig_id: 'WN12-GE-000010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27933r476574_fix'
  tag 'documentable'
  tag legacy: ['SV-52858', 'V-1119']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
