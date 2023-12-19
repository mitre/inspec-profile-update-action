control 'SV-99007' do
  title 'The SLES for vRealize must audit all account creations.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply create a new account. Auditing of account creation mitigates this risk.

To address access requirements, many SLES for vRealize operating systems may be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', %q(Determine if execution of the useradd and groupadd executable are audited.

# auditctl -l | egrep '(useradd|groupadd)'

If either "useradd" or "groupadd" are not listed with a permissions filter of at least "x", this is a finding.

Expected result:
LIST_RULES: exit,always watch=/usr/sbin/useradd perm=x key=useradd
LIST_RULES: exit,always watch=/usr/sbin/groupadd perm=x key=groupadd)
  desc 'fix', 'Configure execute auditing of the "useradd" and "groupadd" executables run the DoD.script with the following command as root:

# /etc/dodscript.sh

OR

Configure execute auditing of the "useradd" and "groupadd" executables. 

Add the following to /etc/audit/audit.rules:
-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

Restart the auditd service. 

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88049r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88357'
  tag rid: 'SV-99007r1_rule'
  tag stig_id: 'VROM-SL-000015'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-95099r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
