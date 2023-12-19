control 'SV-239577' do
  title 'The SLES for vRealize must audit all account-disabling actions.'
  desc 'When SLES for vRealize accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the SLES for vRealize processes themselves. In order to detect and respond to events affecting user accessibility and system processing, SLES for vRealize must audit account disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that SLES for vRealize accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many SLES for vRealize systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Determine if execution of the "passwd" executable is audited: 

# auditctl -l | grep watch=/usr/bin/passwd 

If "/usr/bin/passwd" is not listed with a permissions filter of at least "x", this is a finding.'
  desc 'fix', "Configure SLES for vRealize to automatically audit account-disabling actions by running the following command:

# /etc/dodscript.sh

OR

# echo '-w /usr/bin/passwd -p x -k passwd' >> /etc/audit/audit.rules

Restart the auditd service. 

# service auditd restart"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42810r662180_chk'
  tag severity: 'medium'
  tag gid: 'V-239577'
  tag rid: 'SV-239577r662182_rule'
  tag stig_id: 'VROM-SL-000855'
  tag gtitle: 'SRG-OS-000240-GPOS-00090'
  tag fix_id: 'F-42769r662181_fix'
  tag 'documentable'
  tag legacy: ['SV-99275', 'V-88625']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
