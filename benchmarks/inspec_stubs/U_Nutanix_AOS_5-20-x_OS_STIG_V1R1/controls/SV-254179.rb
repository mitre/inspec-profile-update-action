control 'SV-254179' do
  title 'Nutanix AOS must offload audit records to a syslog server.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration. Offloading is a common process in information systems with limited audit storage capacity.

'
  desc 'check', 'Confirm Nutanix AOS is configured to offload the audit records to a site-specific syslog server.

$ sudo grep @ /etc/rsyslog.d/rsyslog-nutanix.conf
local0.*; @remote-log-host:514

If there are no lines in the "/etc/rsyslog.d/rsyslog-nutanix.conf" files that contain the "@" or "@@" symbol(s), and the lines with the correct symbol(s) to send output to another system do not cover all "rsyslog" output, ask the System Administrator to indicate how the audit logs are offloaded to a different system or media.

If the lines are commented out or there is no evidence that the audit logs are being sent to another system, this is a finding.'
  desc 'fix', 'Configure AOS to offload audit records to site specific syslog server by running the following command.

ncli rsyslog-config add-server name=[alias_of_central_host] ip-address=[IP_of_central_host] port=[port_of_central_host] network-protocol=tcp|udp|relp relp-enabled=yes|no; ncli rsyslog-config add-module module-name=syslog_module level=info server-name=[alias_of_central_host]'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57664r846623_chk'
  tag severity: 'medium'
  tag gid: 'V-254179'
  tag rid: 'SV-254179r846625_rule'
  tag stig_id: 'NUTX-OS-000770'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-57615r846624_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
