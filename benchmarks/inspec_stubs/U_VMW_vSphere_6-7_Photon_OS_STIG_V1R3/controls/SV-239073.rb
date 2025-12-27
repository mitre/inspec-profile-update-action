control 'SV-239073' do
  title 'The Photon operating system must audit all account creations.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to create an account. Auditing account creation actions provides logging that can be used for forensic purposes.'
  desc 'check', 'At the command line, execute the following command:

# auditctl -l | grep -E "(useradd|groupadd)"

Expected result:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

If either "useradd" or "groupadd" are not listed with a permissions filter of at least "x", this is a finding.

Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done as part of a separate control.'
  desc 'fix', 'Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the following lines:

-w /usr/sbin/useradd -p x -k useradd
-w /usr/sbin/groupadd -p x -k groupadd

At the command line, execute the following command:

# /sbin/augenrules --load'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42284r816593_chk'
  tag severity: 'medium'
  tag gid: 'V-239073'
  tag rid: 'SV-239073r816595_rule'
  tag stig_id: 'PHTN-67-000001'
  tag gtitle: 'SRG-OS-000004-GPOS-00004'
  tag fix_id: 'F-42243r816594_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
