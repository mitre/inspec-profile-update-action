control 'SV-239640' do
  title 'The SLES for vRealize must generate audit records for all account creations, modifications, disabling, and termination events.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Determine if execution of the "usermod" and "groupmod" executable are audited:

# auditctl -l | egrep '(usermod|groupmod)'

If either "useradd" or "groupadd" are not listed with a permissions filter of at least "x", this is a finding.

Determine if execution of the "userdel" and "groupdel" executable are audited:

# auditctl -l | egrep '(userdel|groupdel)'

If either "userdel" or "groupdel" are not listed with a permissions filter of at least "x", this is a finding.

Determine if execution of "useradd" and "groupadd" are audited:

# auditctl -l | egrep '(useradd|groupadd)'

If either "useradd" or "groupadd" are not listed with a permissions filter of at least "x", this is a finding.

Determine if execution of the passwd executable is audited: 

# auditctl -l | grep "/usr/bin/passwd" 

If "/usr/bin/passwd" is not listed with a permissions filter of at least "x", this is a finding.

Determine if "/etc/passwd", "/etc/shadow", "/etc/group", and "/etc/security/opasswd" are audited for writing:

# auditctl -l | egrep '(/etc/passwd|/etc/shadow|/etc/group|/etc/security/opasswd)'

If any of these are not listed with a permissions filter of at least "w", this is a finding.)
  desc 'fix', 'Configure execute auditing of the "usermod" and "groupmod" executables. Add the following to the "/etc/audit/audit.rules" file:

-w /usr/sbin/usermod -p x -k usermod
-w /usr/sbin/groupmod -p x -k groupmod

Configure execute auditing of the "userdel" and "groupdel" executables. Add the following to the "/etc/audit/audit.rules" file:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel

Configure execute auditing of the "useradd" and "groupadd" executables. Add the following to audit.rules:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

Configure execute auditing of the "passwd" executable. Add the following to audit.rules:

-w /usr/bin/passwd -p x -k passwd

Configure write auditing of the "passwd", "shadow", "group", and "opasswd" files. Add the following to the "/etc/audit/audit.rules" file:

-w /etc/passwd -p wa -k passwd
-w /etc/shadow -p wa -k shadow
-w /etc/group -p wa -k group
-w /etc/security/opasswd -p wa -k opasswd

Restart the auditd service:

# service auditd restart

OR

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42873r662369_chk'
  tag severity: 'medium'
  tag gid: 'V-239640'
  tag rid: 'SV-239640r662371_rule'
  tag stig_id: 'VROM-SL-001455'
  tag gtitle: 'SRG-OS-000476-GPOS-00221'
  tag fix_id: 'F-42832r662370_fix'
  tag 'documentable'
  tag legacy: ['SV-99401', 'V-88751']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
