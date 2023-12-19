control 'SV-253359' do
  title 'Run as different user must be removed from context menus.'
  desc 'The "Run as different user" selection from context menus allows the use of credentials other than the currently logged on user. Using privileged credentials in a standard user session can expose those credentials to theft. Removing this option from context menus helps prevent this from occurring.'
  desc 'check', 'If the following registry values do not exist or are not configured as specified, this is a finding.
The policy configures the same Value Name, Type and Value under four different registry paths.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Paths: 
\\SOFTWARE\\Classes\\batfile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\cmdfile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\exefile\\shell\\runasuser\\
\\SOFTWARE\\Classes\\mscfile\\shell\\runasuser\\

Value Name: SuppressionPolicy

Type: REG_DWORD
Value: 0x00001000 (4096)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >> "Remove "Run as Different User" from context menus" to "Enabled".

This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and "SecGuide.adml" must be copied to the \\Windows\\PolicyDefinitions and \\Windows\\PolicyDefinitions\\en-US directories respectively.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56812r829159_chk'
  tag severity: 'medium'
  tag gid: 'V-253359'
  tag rid: 'SV-253359r829161_rule'
  tag stig_id: 'WN11-CC-000039'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56762r829160_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
