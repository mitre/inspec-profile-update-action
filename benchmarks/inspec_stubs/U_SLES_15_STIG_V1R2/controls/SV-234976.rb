control 'SV-234976' do
  title 'The SUSE operating system must generate audit records for the /var/log/wtmp file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for the "/var/log/wtmp" file.

Check that the file is being audited by performing the following command:

> sudo auditctl -l | grep -w '/var/log/wtmp'

-w /var/log/wtmp -p wa -k login_mod

If the command does not return a line that matches the example, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for the "/var/log/wtmp" file. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-w /var/log/wtmp -p wa -k login_mod

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38164r619197_chk'
  tag severity: 'medium'
  tag gid: 'V-234976'
  tag rid: 'SV-234976r622137_rule'
  tag stig_id: 'SLES-15-030770'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-38127r619198_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
