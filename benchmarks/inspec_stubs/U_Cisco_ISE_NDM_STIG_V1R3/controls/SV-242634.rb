control 'SV-242634' do
  title 'The Cisco ISE must be running an operating system release that is currently supported by the vendor.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities.

The recommended best practice is for the organization to implement a patch management process for Junos OS. The process should involve testing and verification of the authenticity of vendor-provided updated. These files are then placed into a repository which is protected by access, confidentiality, and integrity control. System administrators can then initiate firmware/software updates by pointing the device to this repository. There is no need for the device to perform additional certificate verification.'
  desc 'check', 'To display information about the software version, type the following at the CLI:
show version

View details about the installed version of Cisco ADE-OS software running in the Cisco ISE server and also the Cisco ISE version.

If the Cisco ISE is not running an operating system release that is currently supported by the vendor, this is a finding.'
  desc 'fix', 'Install the latest approved update of the CISCO ADE-OS software.

1. Click the "Upgrade" tab in the Admin portal.
2. Click "Proceed". The Review Checklist window appears. Read the instructions carefully.
3. Check the "I have reviewed the checklist" check box, and click "Continue".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45909r714210_chk'
  tag severity: 'medium'
  tag gid: 'V-242634'
  tag rid: 'SV-242634r714212_rule'
  tag stig_id: 'CSCO-NM-000280'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-45866r714211_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
