control 'SV-29664' do
  title 'Booting into alternate operating systems is permitted.'
  desc 'Allowing other operating systems to run on a secure system, can allow users to circumvent security.  If more than one operating system is installed on a computer, each must be configured to be compliant with STIG guidance.'
  desc 'check', 'Open the Control Panel 
Double-click on the “System” applet. 
Click on the “Advanced System Settings” link.
Click on the “Advanced” tab. 
Click the Startup and Recovery “Settings” button. 

If the drop-down listbox in System Startup shows any operating system other than the current Windows OS, this may be a finding. If all additional operating systems are STIG compliant, then this is not a finding.'
  desc 'fix', 'Configure the system to prevent running non-compliant alternate operating systems.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-19596r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1119'
  tag rid: 'SV-29664r1_rule'
  tag gtitle: 'Booting into Multiple Operating Systems'
  tag fix_id: 'F-5811r1_fix'
  tag false_positives: 'Review each alternate OS boot option with the SA.'
  tag 'documentable'
  tag potential_impacts: 'The system is not configured to prevent booting into non-compliant alternate operating systems.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
