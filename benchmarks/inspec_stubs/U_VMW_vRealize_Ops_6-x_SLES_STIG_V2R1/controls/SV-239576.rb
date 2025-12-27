control 'SV-239576' do
  title 'The SLES for vRealize must audit all account modifications.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply modify an existing account. Auditing of account modification is one method for mitigating this risk.

To address access requirements, many SLES for vRealize systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', %q(Determine if "/etc/passwd", "/etc/shadow", "/etc/group", and "/etc/gshadow" are audited for writing.

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow)' | grep perm=w

If any of these are not listed with a permissions filter of at least "w", this is a finding.)
  desc 'fix', 'Configure append auditing of the "passwd", "shadow", "group", and "gshadow" files run the DoD.script with the following command as root:

# /etc/dodscript.sh

OR

Configure append auditing of the "passwd", "shadow", "group", and "gshadow" files. Add the following to the audit.rules file: 

-w /etc/passwd -p w -k passwd
-w /etc/shadow -p w -k shadow
-w /etc/group -p w -k group
-w /etc/gshadow -p w -k gshadow

Restart the auditd service. 

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42809r662177_chk'
  tag severity: 'medium'
  tag gid: 'V-239576'
  tag rid: 'SV-239576r662179_rule'
  tag stig_id: 'VROM-SL-000850'
  tag gtitle: 'SRG-OS-000239-GPOS-00089'
  tag fix_id: 'F-42768r662178_fix'
  tag 'documentable'
  tag legacy: ['SV-99273', 'V-88623']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
