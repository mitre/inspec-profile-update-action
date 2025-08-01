control 'SV-76935' do
  title 'ColdFusion must contain the most recent update.'
  desc 'ColdFusion releases updates to ColdFusion 11 to add support, fix bugs and close security issues.  Without the current update installed, the product may be unstable or become a target for an attacker who can take advantage of a known exploit.  The updates, when available, must be tested and installed as soon as possible.'
  desc 'check', 'Within the Administrator Console, navigate to the "Updates" page under the "Server Update" menu.

If the "Available Updates" tab is showing that updates are available, this is a finding.

A list of updates available can be retrieved from the update site.  Enter the "Settings" tab and copy the URL listed in the "Site URL" field.  Paste the URL into a browser and make note of the newest update available.  If the "Site URL" field is empty or if a local update server is being used and the site does not list the updates, the ColdFusion update site can be reached at https://helpx.adobe.com/coldfusion/kb/coldfusion-11-updates.html

Enter the "Installed Updates" tab and verify that the update installed is the latest listed on the update site.

If the latest update is not installed, this is a finding.'
  desc 'fix', 'Navigate to the "Update" page under the "Server Update" menu.  Enter the "Available Updates" tab and install the latest patch available.  If the ColdFusion server is patched from the command line and not through the ColdFusion Console,  the latest patch must be downloaded manually, the hash value verified and then installed using the instructions provided with the patch.'
  impact 0.7
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63249r1_chk'
  tag severity: 'high'
  tag gid: 'V-62445'
  tag rid: 'SV-76935r1_rule'
  tag stig_id: 'CF11-03-000117'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-68365r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
