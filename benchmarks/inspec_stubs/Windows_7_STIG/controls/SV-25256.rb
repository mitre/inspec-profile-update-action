control 'SV-25256' do
  title 'Booting into alternate operating systems is permitted.'
  desc 'Allowing other operating systems to run on a secure system, can allow users to circumvent security.  If more than one operating system is installed on a computer, each must be configured to be compliant with STIG guidance.'
  desc 'check', 'Verify that the local system boots directly into Windows:

Open Control Panel.
Select “System”.
Select the “Advanced System Settings” link.
Select the “Advanced” tab.
Click the Startup and Recovery “Settings” button.  

If the drop-down list box “Default operating system:” shows any operating system other than Windows 7, this may be a finding.

Verify that Windows XP Mode, a Windows Virtual PC instance of Windows XP, has not been installed on the system:

Open Control Panel.
Select “Programs and Features”.
If Windows Virtual PC or Windows XP Mode are listed this may be a finding.

If all additional operating systems are STIG compliant, then this is not a finding.'
  desc 'fix', 'Configure the system to prevent running non-compliant alternate operating systems.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1119'
  tag rid: 'SV-25256r1_rule'
  tag gtitle: 'Booting into Multiple Operating Systems'
  tag fix_id: 'F-5811r1_fix'
  tag false_positives: 'Review each alternate OS boot option with the SA.'
  tag 'documentable'
  tag potential_impacts: 'The system is not configured to prevent running non-compliant alternate operating systems.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
