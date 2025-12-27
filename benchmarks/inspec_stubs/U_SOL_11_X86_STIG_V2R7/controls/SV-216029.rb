control 'SV-216029' do
  title 'The audit system must be configured to audit all administrative, privileged, and security actions.'
  desc 'Without auditing, individual system accesses cannot be tracked, and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'The Audit Configuration profile is required.

This check applies to the global zone only. Determine the zone currently being secured.

# zonename

If the command output is  "global ", this check applies.

Determine the OS version currently being secured.
# uname -v

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -getflags | grep active | cut -f2 -d=

If  "as " audit flag is not included in output, this is a finding.

For Solaris 11.4 or newer:
# pfexec auditconfig -t -getflags | cut -f2 -d=

If  "fm,fd,ft,lo,ap,ss,as,ua,pe,-fa,-ps,-ex " audit flags are not included in the output, this is a finding.

Determine if auditing policy is set to collect command line arguments.

# pfexec auditconfig -getpolicy | grep active | grep argv

If the active audit policies line does not appear, this is a finding.'
  desc 'fix', 'The Audit Configuration profile is required. All audit flags must be enabled in a single command.

This action applies to the global zone only. Determine the zone currently being secured.

# zonename

If the command output is  "global ", this action applies.

For Solaris 11, 11.1, 11.2, and 11.3:
# pfexec auditconfig -setflags cusa,-ps,fd,-fa,fm

For Solaris 11.4 or newer:
# pfexec auditconfig -setflags cusa,-fa,-ex,-ps,fd,fm

Enable the audit policy to collect command line arguments.

# pfexec auditconfig -setpolicy +argv

These changes will not affect users that are currently logged in.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17267r877457_chk'
  tag severity: 'medium'
  tag gid: 'V-216029'
  tag rid: 'SV-216029r877459_rule'
  tag stig_id: 'SOL-11.1-010300'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17265r877458_fix'
  tag 'documentable'
  tag legacy: ['V-47817', 'SV-60693']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
