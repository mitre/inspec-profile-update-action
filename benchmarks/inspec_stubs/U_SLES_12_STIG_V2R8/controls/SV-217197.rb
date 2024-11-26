control 'SV-217197' do
  title 'The audit-audispd-plugins must be installed on the SUSE operating system.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify that the "audit-audispd-plugins" package is installed on the SUSE operating system. 

Check that the "audit-audispd-plugins" package is installed on the SUSE operating system with the following command:

# zypper se audit-audispd-plugins

If the "audit-audispd-plugins" package is not installed, this is a finding.

Verify the "au-remote" plugin is enabled with the following command: 

# grep -i active /etc/audisp/plugins.d/au-remote.conf 
active = yes

If "active" is missing, commented out, or is not set to "yes", this is a finding.'
  desc 'fix', 'Install the "audit-audispd-plugins" package on the SUSE operating system by running the following command:

# sudo zypper install audit-audispd-plugins

In /etc/audisp/plugins.d/au-remote.conf, change the value of "active" to "yes", or add "active = yes" if no such setting exists in the file.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18425r369747_chk'
  tag severity: 'medium'
  tag gid: 'V-217197'
  tag rid: 'SV-217197r854102_rule'
  tag stig_id: 'SLES-12-020070'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-18423r369748_fix'
  tag 'documentable'
  tag legacy: ['SV-91997', 'V-77301']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
