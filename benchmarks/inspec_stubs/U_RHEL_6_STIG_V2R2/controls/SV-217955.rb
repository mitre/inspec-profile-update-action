control 'SV-217955' do
  title 'The audit system must be configured to audit all attempts to alter system time through /etc/localtime.'
  desc 'Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.'
  desc 'check', 'To determine if the system is configured to audit attempts to alter time via the /etc/localtime file, run the following command: 

$ sudo grep -w "/etc/localtime" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

If the system is not configured to audit time changes, this is a finding.'
  desc 'fix', 'Add the following to "/etc/audit/audit.rules": 

-w /etc/localtime -p wa -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport and should always be used.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19436r376880_chk'
  tag severity: 'low'
  tag gid: 'V-217955'
  tag rid: 'SV-217955r603264_rule'
  tag stig_id: 'RHEL-06-000173'
  tag gtitle: 'SRG-OS-000062'
  tag fix_id: 'F-19434r376881_fix'
  tag 'documentable'
  tag legacy: ['V-38530', 'SV-50331']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
