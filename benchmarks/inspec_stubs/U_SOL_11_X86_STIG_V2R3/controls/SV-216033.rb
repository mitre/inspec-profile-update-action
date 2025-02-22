control 'SV-216033' do
  title 'The audit system must be configured to audit failed attempts to access files and programs.'
  desc 'Without auditing, individual system accesses cannot be tracked, and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'The Audit Configuration profile is required.

Check that the audit flag for auditing file access is enabled.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine the OS version you are currently securing.
# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -getflags | grep active | cut -f2 -d=

If "-fa" and "-ps" audit flags are not displayed, this is a finding.

For Solaris 11.4 or newer:
# pfexec auditconfig -t -getflags | cut -f2 -d=

If "-fa", "-ex", and "-ps" audit flags are not displayed, this is a finding.

Determine if auditing policy is set to collect command line arguments.

# pfexec auditconfig -getpolicy | grep active | grep argv

If the active audit policies line does not appear, this is a finding.'
  desc 'fix', 'The Audit Configuration profile is required. All audit flags must be enabled in a single command.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -setflags cusa,-ps,fd,-fa,fm

For Solaris 11.4 or newer:
# pfexec auditconfig -setflags cusa,-fa,-ex,-ps,fd,fm

Enable the audit policy to collect command line arguments.

# pfexec auditconfig -setpolicy +argv

These changes will not affect users that are currently logged in.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17271r372481_chk'
  tag severity: 'low'
  tag gid: 'V-216033'
  tag rid: 'SV-216033r603268_rule'
  tag stig_id: 'SOL-11.1-010340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17269r372482_fix'
  tag 'documentable'
  tag legacy: ['V-47825', 'SV-60701']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
