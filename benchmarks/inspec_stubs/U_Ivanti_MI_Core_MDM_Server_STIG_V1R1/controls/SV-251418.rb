control 'SV-251418' do
  title 'The Ivanti MobileIron Core server must be maintained at a supported version.'
  desc 'The UEM vendor maintains specific product versions for a specific period of time. MDM/EMM server versions no longer supported by the vendor will not receive security updates for new vulnerabilities, which leaves them subject to exploitation.

'
  desc 'check', 'Verify the Core server version is a supported version. This requirement is Not Applicable for the cloud version of Core.

Find the list of currently supported on-prem versions of Core server here: https://help.ivanti.com/mi/help/en_us/EML/3.16.1/rni/Content/EmailPlusiOSReleaseNotes/Support_and_compatibilit.htm

Log onto the Core console and determine the installed version of Core:
1. Click on the round person icon in the top right corner of the Core console.
2. In the drop-down menu, select "About".
3. View the version of Core that is installed.
4. Verify the version is a supported version.

If the installed version of the Core server is not a supported version, this is a finding.'
  desc 'fix', 'Update Core to the most current version. If using the cloud version of Core, this requirement is automatically met.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54853r806384_chk'
  tag severity: 'high'
  tag gid: 'V-251418'
  tag rid: 'SV-251418r806386_rule'
  tag stig_id: 'IMIC-11-010800'
  tag gtitle: 'SRG-APP-000456-UEM-000330'
  tag fix_id: 'F-54806r806385_fix'
  tag satisfies: ['FPT_TUD_EXT.1.1', 'FPT_TUD_EXT.1.2 \nReference: PP-MDM-414005']
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
