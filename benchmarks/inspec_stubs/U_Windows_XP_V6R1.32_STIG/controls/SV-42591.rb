control 'SV-42591' do
  title 'The DoD Interoperability Root CA 1 to DoD Root CA 2 cross certificate must be installed.'
  desc 'To ensure that users do not experience denial of service on NIPRNet when performing certificate-based authentication to DoD websites due to the system chaining to a root other than DoD Root CA 2, the DoD Interoperability Root CA 1 to DoD Root CA 2 cross certificate must be installed in the Untrusted Certificate Store.  This requirement only applies to NIPRNet systems.'
  desc 'check', 'Verify the DoD Root CA 2 certificate issued by DoD Interoperability Root CA 1 is installed on NIPRNet systems as an Untrusted Certificate using the Certificates MMC snap-in.
Run “MMC”
Select “File”, “Add/Remove Snap-in…”
Click “Add…”
Select “Certificates”, click “Add”
Select “Computer account”, click “Next”
Select “Local computer: (the computer this console is running on)”, click “Finish”
Click “Close”
Click “OK”	
Expand “Certificates” and navigate to “Untrusted Certificates\\Certificates”
Search in the right pane for “DoD Root CA 2” under “Issued To” with “DoD Interoperability Root CA 1” as “Issued By”

If there is no entry for “DoD Root CA 2”, this is a finding.

Select “DoD Root CA 2”
Right click and select “Open”
Select the “Details” Tab
Scroll to the bottom and select “Thumbprint Algorithm”
Verify the Value is “sha1”, 

If the value for “Thumbprint Algorithm” is not “sha1”, this is a finding.

Next select “Thumbprint”

If the value for the “Thumbprint” field is not
“99:c4:94:ec:e4:fc:09:3e:ee:13:c4:d6:5b:1b:1e:01:b9:b5:d4:34”, this is a finding.'
  desc 'fix', 'Install the DoD Interoperability Root CA 1 to DoD Root CA 2 cross certificate on NIPRNet systems only.  The FBCA Cross-Certificate Remover tool is available on IASE at http://iase.disa.mil/pki-pke/function_pages/tools.html'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-49164r1_chk'
  tag severity: 'medium'
  tag gid: 'V-32274'
  tag rid: 'SV-42591r4_rule'
  tag stig_id: 'WINPK-000003'
  tag gtitle: 'WINPK-000003 DoD Interoperability Root CA 1 to DoD Root CA 2 cross certificate'
  tag fix_id: 'F-48590r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IATS-1, IATS-2'
end
