control 'SV-240483' do
  title 'The SLES for vRealize must audit all account modifications.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Auditing of account modification is one method for mitigating this risk.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', %q(Determine if /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow are audited for writing.

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)' | grep perm=w

If any of these are not listed with a permissions filter of at least "w", this is a finding.)
  desc 'fix', 'Configure append auditing of the "passwd", "shadow", "group", and "gshadow" files run "dodscript" with the following command as "root":

# /etc/dodscript.sh

OR

Configure auditing of the "passwd", "shadow", "group", and "gshadow" files. Add the following to the audit.rules file:
-w /etc/passwd -p w -k passwd
-w /etc/shadow -p w -k shadow
-w /etc/group -p w -k group
-w /etc/gshadow -p w -k gshadow

Restart the auditd service:
   
# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43716r671188_chk'
  tag severity: 'medium'
  tag gid: 'V-240483'
  tag rid: 'SV-240483r671190_rule'
  tag stig_id: 'VRAU-SL-000875'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag fix_id: 'F-43675r671189_fix'
  tag 'documentable'
  tag legacy: ['SV-100393', 'V-89743']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
