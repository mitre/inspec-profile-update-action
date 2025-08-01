control 'SV-100425' do
  title 'The SLES for vRealize must audit all account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail, which documents the creation of operating system user accounts and notifies System Administrators and Information System Security Officers (ISSO) that it exists. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', %q(Determine if execution of the "usermod" and "groupmod" executable are audited:

# auditctl -l | egrep '(usermod|groupmod)'

If either "usermod" or "groupmod" are not listed with a permissions filter of at least "x", this is a finding.

Determine if execution of the "userdel" and "groupdel" executable are audited:

# auditctl -l | egrep '(userdel|groupdel)'

If either "userdel" or "groupdel" are not listed with a permissions filter of at least "x", this is a finding.

Determine if execution of "useradd" and "groupadd" are audited:

# auditctl -l | egrep '(useradd|groupadd)'

If either "useradd" or "groupadd" are not listed with a permissions filter of at least "x", this is a finding.

Determine if execution of the "passwd" executable is audited: 

# auditctl -l | grep “/usr/bin/passwd” 

If "/usr/bin/passwd" is not listed with a permissions filter of at least "x", this is a finding. 

Determine if /etc/passwd, /etc/shadow, /etc/group, and /etc/security/opasswd are audited for writing:

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/security/opasswd)'

If any of these are not listed with a permissions filter of at least "w", this is a finding.)
  desc 'fix', 'Configure "execute" auditing of the "usermod" and "groupmod" executables. Add the following to the /etc/audit/audit.rules file:

-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod

Configure "execute" auditing of the "userdel" and "groupdel" executables. Add the following to the /etc/audit/audit.rules file:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

Configure "execute" auditing of the "useradd" and "groupadd" executables. Add the following to audit.rules:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

Configure "execute" auditing of the "passwd" executable. Add the following to the aud.rules:

-w /usr/bin/passwd -p x -k passwd

Configure "write" auditing of the "passwd", "shadow", "group", and "opasswd" files. Add the following to the /etc/audit/audit.rules file:

-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/group -p wa -k group
-w /etc/security/opasswd -p wa -k opasswd

Restart the auditd service:

# service auditd restart'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89467r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89775'
  tag rid: 'SV-100425r1_rule'
  tag stig_id: 'VRAU-SL-000995'
  tag gtitle: 'SRG-OS-000303-GPOS-00120'
  tag fix_id: 'F-96517r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
