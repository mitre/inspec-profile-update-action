control 'SV-216030' do
  title 'The audit system must be configured to audit login, logout, and session initiation.'
  desc 'Without auditing, individual system accesses cannot be tracked, and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'The Audit Configuration profile is required.

Check that the audit flag for auditing login and logout is enabled.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine the OS version you are currently securing.
# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -getflags | grep active | cut -f2 -d=

If "lo" audit flag is not included in output, this is a finding

# pfexec auditconfig -getnaflags | grep active | cut -f2 -d=

If "na" and "lo" audit flags are not included in output, this is a finding

For Solaris 11.4 or newer:
# pfexec auditconfig -t -getflags | cut -f2 -d=

If "cusa" audit flag is not included in output, this is a finding

# pfexec auditconfig -t -getnaflags | cut -f2 -d=

If "na" and "lo" audit flags are not included in output, this is a finding

Determine if auditing policy is set to collect command line arguments.

# pfexec auditconfig -getpolicy | grep active | grep argv

If the active audit policies line does not appear, this is a finding.'
  desc 'fix', 'The Audit Configuration profile is required. All audit flags must be enabled in a single command.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -setflags cusa,-ps,fd,-fa,fm
# pfexec auditconfig -setnaflags lo,na

For Solaris 11.4 or newer:
# pfexec auditconfig -setflags cusa,-fa,-ex,-ps,fd,fm
# pfexec auditconfig -setnaflags lo,na

Enable the audit policy to collect command line arguments.

# pfexec auditconfig -setpolicy +argv

These changes will not affect users that are currently logged in.'
  impact 0.3
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17268r372472_chk'
  tag severity: 'low'
  tag gid: 'V-216030'
  tag rid: 'SV-216030r603268_rule'
  tag stig_id: 'SOL-11.1-010310'
  tag gtitle: 'SRG-OS-000032'
  tag fix_id: 'F-17266r372473_fix'
  tag 'documentable'
  tag legacy: ['SV-60695', 'V-47819']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
