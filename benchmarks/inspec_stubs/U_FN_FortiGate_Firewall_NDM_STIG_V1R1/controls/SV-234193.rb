control 'SV-234193' do
  title 'The FortiGate device must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.'
  desc 'check', 'Log in to the Fortinet Support Portal and review the Product Life Cycle Software "End of Support Date". 

Log in to the FortiGate with Super-Admin privilege in the GUI and review the Dashboard >> Status >> System Information widget for Firmware version. 

If the firmware listed in the FortiGate is not supported based on the Product Life Cycle page, this is a finding.'
  desc 'fix', 'Go to the Fortinet Upgrade Path Tool and select the platform that is being upgraded, the current FortiOS version, and the desired FortiOS version, and then click "Go". 

Log in to the Fortinet Support Portal and go to Download >> Firmware Images and download the listed firmware versions from the Upgrade Path Tool. 

Log in to the FortiGate GUI with Super-Admin privilege and go to System >> Firmware. Upload the target firmware file under "Upload Firmware >> Browse" and then click "Backup config and upgrade”. 

Repeat as necessary as defined by the Upgrade Path Tool.'
  impact 0.7
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37378r611766_chk'
  tag severity: 'high'
  tag gid: 'V-234193'
  tag rid: 'SV-234193r628777_rule'
  tag stig_id: 'FGFW-ND-000170'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-37343r611767_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
