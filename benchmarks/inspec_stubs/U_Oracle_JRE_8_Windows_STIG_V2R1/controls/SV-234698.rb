control 'SV-234698' do
  title 'Oracle JRE 8 must remove previous versions when the latest version is installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Review the system configuration to ensure old versions of JRE have been removed.

Open the Windows Control Panel, and navigate to "Programs and Features".

Ensure only one instance of JRE is in the list of installed software. If more than one instance of JRE is listed, this is a finding.

Note:  A 32 and 64 bit version of the same instance is acceptable.'
  desc 'fix', 'Remove previous versions of JRE.

Open the Windows Control Panel, and navigate to "Programs and Features".

Highlight, and click uninstall on all out of date instances of JRE.'
  impact 0.5
  ref 'DPMS Target Oracle Java Runtime Environment v8 for Windows'
  tag check_id: 'C-37883r616150_chk'
  tag severity: 'medium'
  tag gid: 'V-234698'
  tag rid: 'SV-234698r617446_rule'
  tag stig_id: 'JRE8-WN-000190'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-37848r616151_fix'
  tag 'documentable'
  tag legacy: ['V-66965', 'SV-81455']
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
