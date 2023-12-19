control 'SV-82751' do
  title 'The Mainframe Product  must provide an immediate warning to the system programmer and security administrator (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  desc 'If security personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion.'
  desc 'check', 'If the Mainframe Product uses MVS  System Management Facility (SMF) recording or external security manager (ESM) log files for auditing purposes, this is not applicable.

Examine the Mainframe Product installation and configuration auditing settings.

If the installation and/or configuration setting for auditing do not provide an immediate warning to the system programmer and security administrator (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product installation and configuration settings for auditing to provide an immediate warning to the system programmer and security administrator (at a minimum) when allocated audit record storage volume reaches 75 percent of repository maximum audit record storage capacity.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68821r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68261'
  tag rid: 'SV-82751r1_rule'
  tag stig_id: 'SRG-APP-000359-MFP-000151'
  tag gtitle: 'SRG-APP-000359-MFP-000151'
  tag fix_id: 'F-74375r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
