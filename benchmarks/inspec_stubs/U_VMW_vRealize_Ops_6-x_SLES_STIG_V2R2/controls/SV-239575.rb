control 'SV-239575' do
  title 'The SLES for vRealize must audit all account modifications.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Auditing of account modification is one method for mitigating this risk.

To address access requirements, many SLES for vRealize systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', %q(Determine if execution of the "usermod" and "groupmod" executable are audited.

# auditctl -l | egrep '(usermod|groupmod)' | grep perm=x

If either "usermod" or "groupmod" are not listed with a permissions filter of at least "x", this is a finding.)
  desc 'fix', 'Configure execute auditing of the "usermod" and "groupmod" executables run the DoD.script with the following command as "root":

# /etc/dodscript.sh

OR

Configure execute auditing of the "usermod" and "groupmod" executables. Add the following to the audit.rules file: 

-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod

Restart the auditd service. 

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42808r662174_chk'
  tag severity: 'medium'
  tag gid: 'V-239575'
  tag rid: 'SV-239575r662176_rule'
  tag stig_id: 'VROM-SL-000845'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag fix_id: 'F-42767r662175_fix'
  tag 'documentable'
  tag legacy: ['SV-99271', 'V-88621']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
