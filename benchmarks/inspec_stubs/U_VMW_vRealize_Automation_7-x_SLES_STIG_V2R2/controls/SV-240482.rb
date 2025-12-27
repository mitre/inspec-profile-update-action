control 'SV-240482' do
  title 'The SLES for vRealize must audit all account modifications.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Auditing of account modification is one method for mitigating this risk.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', "Determine if execution of the usermod and groupmod executable are audited.

# auditctl -l | egrep '(usermod|groupmod)' | grep perm=x

If either usermod or groupmod are not listed with a permissions filter of at least 'x', this is a finding."
  desc 'fix', 'Configure execute auditing of the usermod and groupmod executables run the dodscript with the following command as root:

# /etc/dodscript.sh

OR....

Configure execute auditing of the usermod and groupmod executables. Add the following to the audit.rules file:
-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod

Restart the auditd service.   
# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43715r671185_chk'
  tag severity: 'medium'
  tag gid: 'V-240482'
  tag rid: 'SV-240482r671187_rule'
  tag stig_id: 'VRAU-SL-000870'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag fix_id: 'F-43674r671186_fix'
  tag 'documentable'
  tag legacy: ['SV-100391', 'V-89741']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
