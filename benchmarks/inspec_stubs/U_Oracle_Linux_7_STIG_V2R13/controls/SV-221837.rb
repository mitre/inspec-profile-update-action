control 'SV-221837' do
  title 'The Oracle Linux operating system must use a virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an antivirus solution on the system.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23552r419583_chk'
  tag severity: 'high'
  tag gid: 'V-221837'
  tag rid: 'SV-221837r603260_rule'
  tag stig_id: 'OL07-00-032000'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23541r419584_fix'
  tag 'documentable'
  tag legacy: ['V-99413', 'SV-108517']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
