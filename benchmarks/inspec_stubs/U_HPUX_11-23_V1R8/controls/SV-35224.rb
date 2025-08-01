control 'SV-35224' do
  title 'The system must use and update a DoD-approved virus scan program.'
  desc 'Virus scanning software can be used to protect a system from penetration from computer viruses and to limit their spread through intermediate systems. Virus scanning software is available to DoD on the JTF-GNO website (https://www.jtfgno.mil).

The virus scanning software should be configured to perform scans dynamically on accessed files. If this capability is not available, the system must be configured to scan, at a minimum, all altered files on the system on a daily basis.

If the system processes inbound SMTP mail, the virus scanner must be configured to scan all received mail.'
  desc 'check', 'Check for the existence of the McAfee command line scan tool to be executed weekly in the cron file. Additional tools specific for each operating system are also available and will have to be manually reviewed if they are installed. In addition, the definitions file should not be older than seven (7) days. 

Check if uvscan scheduled to run.
# grep uvscan /var/spool/cron/crontabs/*

If a virus scanner is not being run weekly this is a finding.

If a virus scanner is being run at least weekly, ensure the virus definition signature files are not older than seven (7) days.

# find / -type f -name clean.dat -o -name names.dat -o -name scan.dat | xargs -n1 ls -lLa

If the virus definitions are older than seven (7) days, this is a finding.'
  desc 'fix', 'Install McAfee command line virus scan tool, or an appropriate alternative from https://www.jtfgno.mil.

Ensure the virus signature definition files are no older than seven (7) days.

Updates are also available from https://www.jtfgno.mil.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36734r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12765'
  tag rid: 'SV-35224r2_rule'
  tag stig_id: 'GEN006640'
  tag gtitle: 'GEN006640'
  tag fix_id: 'F-32115r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECVP-1'
  tag cci: ['CCI-001668']
  tag nist: ['SI-3 a']
end
