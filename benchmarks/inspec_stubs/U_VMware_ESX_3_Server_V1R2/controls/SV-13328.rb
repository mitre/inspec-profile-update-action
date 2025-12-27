control 'SV-13328' do
  title 'The system must use and update a DoD-approved virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration by computer viruses and to limit their spread through intermediate systems. Virus scanning software is available to DoD on the JTF-GNO web site.

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Determine if a DoD-approved virus scan program is installed and using updates less than 14 days old.  If not, this is a finding.'
  desc 'fix', 'Install McAfee command line virus scan tool, or an appropriate alternative from https://www.jtfgno.mil.

Ensure the virus signature definition files are no older than seven (7) days.

Updates are also available from https://www.jtfgno.mil.

Ensure the command line virus scan tool is run on a regular basis using a utility, such as cron.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-9295r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12765'
  tag rid: 'SV-13328r2_rule'
  tag stig_id: 'GEN006640'
  tag gtitle: 'GEN006640'
  tag fix_id: 'F-12286r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECVP-1'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
