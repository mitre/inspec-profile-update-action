control 'SV-240484' do
  title 'The SLES for vRealize must audit all account disabling actions.'
  desc 'When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual users or for identifying the operating system processes themselves. In order to detect and respond to events affecting user accessibility and system processing, operating systems must audit account disabling actions and, as required, notify the appropriate individuals so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many operating systems can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Determine if execution of the "passwd" executable is audited: 

# auditctl -l | grep watch=/usr/bin/passwd 

If /usr/bin/passwd is not listed with a permissions filter of at least "x", this is a finding.'
  desc 'fix', "Configure the SLES for vRealize to automatically audit account disabling actions by running the following command:

# /etc/dodscript.sh

OR

# echo '-w /usr/bin/passwd -p x -k passwd' >> /etc/audit/audit.rules

Restart the auditd service:
  
# service auditd restart"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43717r671191_chk'
  tag severity: 'medium'
  tag gid: 'V-240484'
  tag rid: 'SV-240484r671193_rule'
  tag stig_id: 'VRAU-SL-000880'
  tag gtitle: 'SRG-OS-000240-GPOS-00090'
  tag fix_id: 'F-43676r671192_fix'
  tag 'documentable'
  tag legacy: ['SV-100395', 'V-89745']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
