control 'SV-99009' do
  title 'In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications, any unexpected users, groups, or modifications must be investigated for legitimacy.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation mitigates this risk.

To address access requirements, many SLES for vRealize operating systems may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', %q(Determine if /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow are audited for appending.

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)' | grep perm=a

If the "passwd", "shadow", "group", and "gshadow" files are not listed with a permissions filter of at least "a", this is a finding.

Expected result:
LIST_RULES: exit,always watch=/etc/passwd perm=a key=passwd
LIST_RULES: exit,always watch=/etc/shadow perm=a key=shadow
LIST_RULES: exit,always watch=/etc/group perm=a key=group
LIST_RULES: exit,always watch=/etc/gshadow perm=a key=gshadow)
  desc 'fix', %q(Configure append auditing of the "passwd", "shadow", "group", and "gshadow" files run the DoD.script with the following command as root:

# /etc/dodscript.sh
# echo '-w /etc/gshadow -p a -k gshadow' >> /etc/audit/audit.rules

Restart the auditd service.
# service auditd restart

OR

Configure append auditing of the passwd, shadow, group, and gshadow files by running the following commands:

# echo '-w /etc/passwd -p a -k passwd' >> /etc/audit/audit.rules
# echo '-w /etc/shadow -p a -k shadow' >> /etc/audit/audit.rules
# echo '-w /etc/group -p a -k group' >> /etc/audit/audit.rules
# echo '-w /etc/gshadow -p a -k gshadow' >> /etc/audit/audit.rules

Restart the auditd service. 

# service auditd restart)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88051r2_chk'
  tag severity: 'medium'
  tag gid: 'V-88359'
  tag rid: 'SV-99009r1_rule'
  tag stig_id: 'VROM-SL-000020'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-95101r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
