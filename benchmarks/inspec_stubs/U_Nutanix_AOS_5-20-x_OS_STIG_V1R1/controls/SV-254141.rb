control 'SV-254141' do
  title 'Nutanix AOS must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Confirm Nutanix AOS must allow only the Information System Security Manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.

Note: Nutanix AOS audit facility is locked down so that only root has access to browse below the /etc/audit/ directory. 

$ sudo su -
# ls -al /etc/audit/rules.d/*.rules
-rw-r----- 1 root root 1280 Feb 16 17:09 audit.rules

$ sudo su -
sudo stat -c "%a %n" /etc/audit/auditd.conf
640 /etc/audit/auditd.conf

If the files in the "/etc/audit/rules.d/" directory or the "/etc/audit/auditd.conf" file have a mode more permissive than "0640", this is a finding.'
  desc 'fix', 'Configure the files in directory "/etc/audit/rules.d/" and the "/etc/audit/auditd.conf" file to have a mode of "0640" with the following commands:

$ sudo su -
# chmod 0640 /etc/audit/rules.d/audit.rules
# chmod 0640 /etc/audit/rules.d/[customrulesfile].rules
# chmod 0640 /etc/audit/auditd.conf'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57626r846509_chk'
  tag severity: 'medium'
  tag gid: 'V-254141'
  tag rid: 'SV-254141r846511_rule'
  tag stig_id: 'NUTX-OS-000350'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-57577r846510_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
