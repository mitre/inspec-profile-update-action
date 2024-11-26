control 'SV-205554' do
  title 'The Mainframe Product must off-load audit records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'If the Mainframe Product uses MVS System Management Facility (SMF) recording  or external security manager (ESM) log files for auditing purposes, this is not applicable.

Examine the Mainframe Product installation and configuration auditing settings.

If the installation and/or configuration setting for auditing do not require the off-loading of audit records onto a different system or media than the system being audited, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product installation and/or configurations settings to off-load audit records onto a different system or media than the system being audited.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5820r299889_chk'
  tag severity: 'medium'
  tag gid: 'V-205554'
  tag rid: 'SV-205554r851318_rule'
  tag stig_id: 'SRG-APP-000358-MFP-000149'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-5820r299890_fix'
  tag 'documentable'
  tag legacy: ['SV-82749', 'V-68259']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
