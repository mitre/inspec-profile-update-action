control 'SV-42590' do
  title 'The External CA Root Certificate must be installed.'
  desc 'To ensure secure websites protected with ECA server certificates on NIPRNet are properly validated, the system must trust the ECA Root CA 2.  The ECA root certificate will ensure that the trust chain is established for server certificate issued from the External CA.  This requirement only applies to NIPRNet systems.'
  desc 'check', 'Verify the ECA Root CA 2 certificate is installed on NIPRNet systems as a Trusted Root Certification Authority using the Certificates MMC snap-in.
Run “MMC”
Select “File”, “Add/Remove Snap-in…”
Click “Add…”
Select “Certificates”, click “Add”
Select “Computer account”, click “Next”
Select “Local computer: (the computer this console is running on)”, click “Finish”
Click “Close”
Click “OK”
Expand “Certificates” and navigate to “Trusted Root Certification Authorities\\Certificates”
Search for “ECA Root CA 2” under “Issued To” in the center pane 

If there is no entry for “ECA Root CA 2” this is a finding.

Select “ECA Root CA 2”
Right click and select “Open”
Select the “Details” Tab
Scroll to the bottom and select “Thumbprint Algorithm”
Verify the Value is “sha1”, 

If the value for Thumbprint Algorithm is not “sha1” this is a finding.

Next select “Thumbprint” 

If the value for the “Thumbprint” field is not
“c3:13:f9:19:a6:ed:4e:0e:84:51:af:a9:30:fb:41:9a:20:f1:81:e4” this is a finding.'
  desc 'fix', 'Install the ECA root CA 2 certificate on NIPRNet systems only.  The InstallRoot tool is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-49160r1_chk'
  tag severity: 'medium'
  tag gid: 'V-32273'
  tag rid: 'SV-42590r3_rule'
  tag stig_id: 'WINPK-000002'
  tag gtitle: 'WINPK-000002 External CA Root Certificate'
  tag fix_id: 'F-48586r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IATS-1, IATS-2'
end
