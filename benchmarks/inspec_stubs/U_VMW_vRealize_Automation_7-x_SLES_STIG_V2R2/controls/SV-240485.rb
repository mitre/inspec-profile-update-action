control 'SV-240485' do
  title 'The SLES for vRealize must audit all account removal actions.'
  desc 'When operating system accounts are removed, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the operating system processes themselves. In order to detect and respond to events affecting user accessibility and system processing, operating systems must audit account removal actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', %q(Determine if execution of the "userdel" and "groupdel" executable are audited:

# auditctl -l | egrep '(userdel|groupdel)'

If either "userdel" or "groupdel" are not listed with a permissions filter of at least "x", this is a finding.)
  desc 'fix', 'Configure execute auditing of the "userdel" and "groupdel" executables. Add the following to the /etc/audit/audit.rules file:

-w /usr/sbin/userdel -p x -k userdel
-w /usr/sbin/groupdel -p x -k groupdel'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43718r671194_chk'
  tag severity: 'medium'
  tag gid: 'V-240485'
  tag rid: 'SV-240485r671196_rule'
  tag stig_id: 'VRAU-SL-000885'
  tag gtitle: 'SRG-OS-000241-GPOS-00091'
  tag fix_id: 'F-43677r671195_fix'
  tag 'documentable'
  tag legacy: ['SV-100397', 'V-89747']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
