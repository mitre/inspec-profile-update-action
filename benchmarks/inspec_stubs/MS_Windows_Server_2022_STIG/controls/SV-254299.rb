control 'SV-254299' do
  title 'Windows Server 2022 Event Viewer must be protected from unauthorized modification and deletion.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the modification or deletion of audit tools.

'
  desc 'check', 'Navigate to "%SystemRoot%\\System32".

View the permissions on "Eventvwr.exe".

If any groups or accounts other than TrustedInstaller have "Full control" or "Modify" permissions, this is a finding.

The default permissions below satisfy this requirement:

TrustedInstaller - Full Control
Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION PACKAGES - Read & Execute'
  desc 'fix', 'Configure the permissions on the "Eventvwr.exe" file to prevent modification by any groups or accounts other than TrustedInstaller. The default permissions listed below satisfy this requirement:

TrustedInstaller - Full Control
Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION PACKAGES - Read & Execute

The default location is the "%SystemRoot%\\System32" folder.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57784r848711_chk'
  tag severity: 'medium'
  tag gid: 'V-254299'
  tag rid: 'SV-254299r848713_rule'
  tag stig_id: 'WN22-AU-000060'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-57735r848712_fix'
  tag satisfies: ['SRG-OS-000257-GPOS-00098', 'SRG-OS-000258-GPOS-00099']
  tag 'documentable'
  tag cci: ['CCI-001494', 'CCI-001495']
  tag nist: ['AU-9', 'AU-9']
end
