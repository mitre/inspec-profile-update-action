control 'SV-234977' do
  title 'The SUSE operating system must generate audit records for the /var/log/btmp file.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for the "/var/log/btmp" file.

Check that the file is being audited by performing the following command:

> sudo auditctl -l | grep -w '/var/log/btmp'

-w /var/log/btmp -p wa -k login_mod

If the command does not return a line that matches the example, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for the "/var/log/btmp" file. 

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-w /var/log/btmp -p wa -k login_mod

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38165r619200_chk'
  tag severity: 'medium'
  tag gid: 'V-234977'
  tag rid: 'SV-234977r622137_rule'
  tag stig_id: 'SLES-15-030780'
  tag gtitle: 'SRG-OS-000472-GPOS-00217'
  tag fix_id: 'F-38128r619201_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
