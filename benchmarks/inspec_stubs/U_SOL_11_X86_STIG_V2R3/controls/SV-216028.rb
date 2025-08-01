control 'SV-216028' do
  title 'The operating system must ensure unauthorized, security-relevant configuration changes detected are tracked.'
  desc 'Without auditing, malicious activity cannot be detected.'
  desc 'check', 'The Audit Configuration profile is required.

This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

Determine the OS version you are currently securing.
# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -getflags | grep active | cut -f2 -d=

If "as" audit flag is not included in output, this is a finding.

For Solaris 11.4 or newer:
# pfexec auditconfig -t -getflags | cut -f2 -d=

If "cusa" audit flag is not included in output, this is a finding.

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
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17266r372466_chk'
  tag severity: 'medium'
  tag gid: 'V-216028'
  tag rid: 'SV-216028r603268_rule'
  tag stig_id: 'SOL-11.1-010290'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17264r372467_fix'
  tag 'documentable'
  tag legacy: ['V-47815', 'SV-60691']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
