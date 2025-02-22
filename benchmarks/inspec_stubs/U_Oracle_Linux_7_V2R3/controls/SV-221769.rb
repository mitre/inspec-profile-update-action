control 'SV-221769' do
  title 'The Oracle Linux operating system must label all off-loaded audit logs before sending them to the central log server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

One method of off-loading audit logs in Oracle Linux is with the use of the audisp-remote dameon.  When audit logs are not labeled before they are sent to a central log server, the audit data will not be able to be analyzed and tied back to the correct system.

'
  desc 'check', 'Verify the audisp daemon is configured to label all off-loaded audit logs:

# grep "name_format" /etc/audisp/audispd.conf

name_format = hostname

If the "name_format" option is not "hostname", "fqd", or "numeric", or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or storage media, and to indicate if the logs are labeled appropriately.

If there is no evidence that the system is configured to off-load audit logs to a different system or storage media, or if the configuration does not appropriately label logs before they are off-loaded, this is a finding.'
  desc 'fix', 'Edit the /etc/audisp/audispd.conf file and add or update the "name_format" option:

name_format = hostname

The audit daemon must be restarted for changes to take effect:

# service auditd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-36290r602464_chk'
  tag severity: 'medium'
  tag gid: 'V-221769'
  tag rid: 'SV-221769r603260_rule'
  tag stig_id: 'OL07-00-030211'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-36254r602465_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag legacy: ['SV-108381', 'V-99277']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
