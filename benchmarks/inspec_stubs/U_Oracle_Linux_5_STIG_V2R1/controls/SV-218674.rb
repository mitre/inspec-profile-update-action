control 'SV-218674' do
  title 'The Oracle Linux 5 operating system must use a virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems.

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Verify an antivirus solution is installed on the system. The antivirus solution may be bundled with an approved host-based security solution.

If there is no antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'Install an antivirus solution on the system.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20149r561446_chk'
  tag severity: 'medium'
  tag gid: 'V-218674'
  tag rid: 'SV-218674r603259_rule'
  tag stig_id: 'GEN006650'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20147r561447_fix'
  tag 'documentable'
  tag legacy: ['V-81455', 'SV-96169']
  tag cci: ['CCI-000366', 'CCI-001668']
  tag nist: ['CM-6 b', 'SI-3 a']
end
