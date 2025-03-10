control 'SV-226589' do
  title 'Auditing must be implemented.'
  desc 'Without auditing, individual system accesses cannot be tracked and malicious activity cannot be detected and traced back to an individual account.'
  desc 'check', 'Determine the type of zone that you are currently securing.

# zonename

If the output of "zonename" is "global", then auditing must be enabled.

Determine if auditing is enabled.

# ps -ef |grep auditd

If the auditd process is not found, this is a finding.
If the output of "zonename" is not "global", then the "perzone" policy must be determined.

# auditconfig --getpolicy 
audit policies = cnt,perzone

If "perzone" is not listed then this requirement is not applicable.  If "perzone" is listed then determine if auditing is enabled.

# ps -ef |grep auditd

If the auditd process is not found, this is a finding.'
  desc 'fix', 'Use /etc/security/bsmconv to enable auditing on the system.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36395r602788_chk'
  tag severity: 'medium'
  tag gid: 'V-226589'
  tag rid: 'SV-226589r603265_rule'
  tag stig_id: 'GEN002660'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-36359r602789_fix'
  tag 'documentable'
  tag legacy: ['SV-27266', 'V-811']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
