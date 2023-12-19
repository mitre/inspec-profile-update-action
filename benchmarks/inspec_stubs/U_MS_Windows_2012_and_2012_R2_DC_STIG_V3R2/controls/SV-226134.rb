control 'SV-226134' do
  title 'Event Viewer must be protected from unauthorized modification and deletion.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

Operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the modification or deletion of audit tools.'
  desc 'check', 'Verify the permissions on Event Viewer only allow TrustedInstaller permissions to change or modify.  If any groups or accounts other than TrustedInstaller have Full control or Modify, this is a finding.

Navigate to "%SystemRoot%\\SYSTEM32".
View the permissions on "Eventvwr.exe".

The default permissions below satisfy this requirement.
TrustedInstaller - Full Control
Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES - Read & Execute'
  desc 'fix', 'Ensure only TrustedInstaller has permissions to change or modify Event Viewer ("%SystemRoot%\\SYSTEM32\\Eventvwr.exe).

The default permissions below satisfy this requirement.
TrustedInstaller - Full Control
Administrators, SYSTEM, Users, ALL APPLICATION PACKAGES - Read & Execute'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27836r475725_chk'
  tag severity: 'medium'
  tag gid: 'V-226134'
  tag rid: 'SV-226134r569184_rule'
  tag stig_id: 'WN12-AU-000213'
  tag gtitle: 'SRG-OS-000257-GPOS-00098'
  tag fix_id: 'F-27824r475726_fix'
  tag 'documentable'
  tag legacy: ['SV-72135', 'V-57721']
  tag cci: ['CCI-001494', 'CCI-001495']
  tag nist: ['AU-9', 'AU-9']
end
