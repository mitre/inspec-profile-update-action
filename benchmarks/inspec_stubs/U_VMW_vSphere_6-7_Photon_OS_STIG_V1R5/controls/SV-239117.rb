control 'SV-239117' do
  title 'The Photon operating system must audit all account disabling actions.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are used for identifying individual users or the operating system processes themselves. To detect and respond to events affecting user accessibility and system processing, operating systems must audit account disabling actions.'
  desc 'check', 'At the command line, execute the following command:

# auditctl -l | grep "^-w /usr/bin/passwd"

Expected result:

-w /usr/bin/passwd -p x -k passwd

If the output does not match the expected result, this is a finding.

Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done as part of a separate control.'
  desc 'fix', 'Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the following lines:

-w /usr/bin/passwd -p x -k passwd

At the command line, execute the following command:

# /sbin/augenrules --load'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42328r816629_chk'
  tag severity: 'medium'
  tag gid: 'V-239117'
  tag rid: 'SV-239117r816631_rule'
  tag stig_id: 'PHTN-67-000046'
  tag gtitle: 'SRG-OS-000240-GPOS-00090'
  tag fix_id: 'F-42287r816630_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
