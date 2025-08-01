control 'SV-221646' do
  title 'The Workspace ONE UEM server must be maintained at a supported version.'
  desc 'The MDM/EMM vendor maintains specific product versions for a specific period of time. MDM/EMM server versions no longer supported by the vendor will not receive security updates for new vulnerabilities which leaves them subject to exploitation.

SFR ID: FPT_TUD_EXT.1.1, FPT_TUD_EXT.1.2'
  desc 'check', 'Verify the installed version of Workspace ONE UEM server is currently supported.

On the Workspace ONE UEM server console, do the following to determine the version number of the server:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Click "About" on the bottom of the left hand menu. The version and build of the installed software will be displayed.

List of current supported versions: https://www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/support/product-lifecycle-matrix.pdf, scroll to Workspace ONE UEM Console.

If the displayed Workspace ONE server version is not currently supported or is not a newer version than on the list above, this is a finding.'
  desc 'fix', 'Update the Workspace ONE UEM server to a supported version. See (https://www.vmware.com/content/dam/digitalmarketing/vmware/en/pdf/support/product-lifecycle-matrix.pdf) for the list of current Workspace ONE UEM supported versions.

Alternatively, the Knowledge Base article can be used: https://kb.vmware.com/s/article/2960922?lang=en_US&queryTerm=workspace+one+uem+console+release+and+end+of+general+support+matrix&queryTerm=workspace+one+uem+console+release+and+end+of+general+support+matrix'
  impact 0.7
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23361r416776_chk'
  tag severity: 'high'
  tag gid: 'V-221646'
  tag rid: 'SV-221646r588007_rule'
  tag stig_id: 'VMW1-00-000650'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-23350r416777_fix'
  tag 'documentable'
  tag legacy: ['SV-111291', 'V-102335']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
