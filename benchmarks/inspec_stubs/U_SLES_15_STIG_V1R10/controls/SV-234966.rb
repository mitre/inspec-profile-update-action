control 'SV-234966' do
  title 'The audit-audispd-plugins must be installed on the SUSE operating system.'
  desc 'The audit-audispd-plugins must be installed on the SUSE operating system.'
  desc 'check', 'Verify that the "audit-audispd-plugins" package is installed on the SUSE operating system. 

Check that the "audit-audispd-plugins" package is installed on the SUSE operating system with the following command:

> zypper info audit-audispd-plugins | grep Installed

If the "audit-audispd-plugins" package is not installed, this is a finding.

Verify the "au-remote" plugin is enabled with the following command: 

> sudo grep -i active /etc/audisp/plugins.d/au-remote.conf 
active = yes

If "active" is missing, commented out, or is not set to "yes", this is a finding.'
  desc 'fix', 'Install the "audit-audispd-plugins" package on the SUSE operating system by running the following command:

> sudo zypper install audit-audispd-plugins

In "/etc/audisp/plugins.d/au-remote.conf", change the value of "active" to "yes", or add "active = yes" if no such setting exists in the file.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38154r619167_chk'
  tag severity: 'medium'
  tag gid: 'V-234966'
  tag rid: 'SV-234966r877390_rule'
  tag stig_id: 'SLES-15-030670'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-38117r619168_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
