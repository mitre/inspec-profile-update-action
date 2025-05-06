control 'SV-42589' do
  title 'The DoD Root Certificate must be installed.'
  desc 'To ensure secure DoD websites and DoD signed code are properly validated, the system must trust the DoD Root CA 2.  The DOD root certificate will ensure that the trust chain is established for server certificates issued from the DOD CA.'
  desc 'check', 'Verify the DoD Root CA 2 certificate is installed as a Trusted Root Certification Authority using the Certificates MMC snap-in.
Run “MMC”
Select “File”, “Add/Remove Snap-in…”
Click “Add…”
Select “Certificates”, click “Add”
Select “Computer account”, click “Next”
Select “Local computer: (the computer this console is running on)”, click “Finish”
Click “Close”
Click “OK”
Expand “Certificates” and navigate to “Trusted Root Certification Authorities\\Certificates”
Search for “DoD Root CA 2” under “Issued To” in the center pane 

If there is no entry for “DoD Root CA 2” this is a finding.

Select DoD Root CA 2
Right click and select “Open”
Select the “Details” Tab
Scroll to the bottom and select “Thumbprint Algorithm”
Verify the Value is “sha1”, 

If the value for “Thumbprint Algorithm” is not “sha1” this is a finding.

Next select “Thumbprint” 

If the value for the “Thumbprint” field is not
“8C:94:1B:34:EA:1E:A6:ED:9A:E2:BC:54:CF:68:72:52:B4:C9:B5:61” this is a finding.
The thumbprint referenced applies to NIPRNet, see PKE documentation for other networks.'
  desc 'fix', 'Install the DoD Root CA 2 certificate. The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-49222r1_chk'
  tag severity: 'medium'
  tag gid: 'V-32272'
  tag rid: 'SV-42589r3_rule'
  tag stig_id: 'WINPK-000001'
  tag gtitle: 'WINPK-000001 DoD Root Certificate'
  tag fix_id: 'F-48782r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IATS-1, IATS-2'
end
