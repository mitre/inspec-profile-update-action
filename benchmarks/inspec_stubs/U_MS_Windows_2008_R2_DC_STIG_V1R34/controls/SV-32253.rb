control 'SV-32253' do
  title 'Booting into alternate non STIG compliant operating systems will not be permitted.'
  desc 'Allowing other operating systems to run on a secure system, can allow users to circumvent security.  If more than one operating system is installed on a computer each must be configured to be compliant with STIG guidance.'
  desc 'check', 'Open the Control.
Panel Double-click on the “System” applet. 
Click on the “Advanced System Settings” link. 
Click the Startup and Recovery “Settings” button. 

If the drop-down listbox in System Startup shows any operating system other than the current Windows OS, this may be a finding. If all additional operating systems are STIG compliant, then this is not a finding.'
  desc 'fix', 'Remove any non STIG compliant alternate operating systems.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32850r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1119'
  tag rid: 'SV-32253r1_rule'
  tag gtitle: 'Booting into Multiple Operating Systems'
  tag fix_id: 'F-28961r1_fix'
  tag false_positives: 'Review each alternate OS boot option for STIG compliance with the SA.'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
