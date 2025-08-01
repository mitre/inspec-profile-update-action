control 'SV-257521' do
  title 'OpenShift audit records must have a date and time association with all events.'
  desc 'Within the container platform, audit data can be generated from any of the deployed container platform components. This audit data is important when there are issues, such as security incidents, that must be investigated. To make the audit data worthwhile for the investigation of events, it is necessary to know when the event occurred. To establish the time of the event, the audit record must contain the date and time.'
  desc 'check', %q(1. Verify Red Hat Enterprise Linux CoreOS (RHCOS) Audit Daemon is configured to resolve audit information before writing to disk by executing the following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep "log_format" /etc/audit/auditd.conf' 2>/dev/null; done

If the "log_format" option is not "ENRICHED", or the line is missing or commented out, this is a finding.

2. Verify RHCOS takes the appropriate action when an audit processing failure occurs.

Verify RHCOS takes the appropriate action when an audit processing failure occurs by executing following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep disk_error_action /etc/audit/auditd.conf' 2>/dev/null; done

If the value of the "disk_error_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is missing or commented out, ask the system administrator to indicate how the system takes appropriate action when an audit process failure occurs. If there is no evidence of appropriate action, this is a finding.

3. Verify the SA and ISSO (at a minimum) are notified when the audit storage volume is full.

Check which action RHEL takes when the audit storage volume is full by executing the following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; grep max_log_file_action /etc/audit/auditd.conf' 2>/dev/null; done

If the value of the "max_log_file_action" option is set to "ignore", "rotate", or "suspend", or the line is missing or commented out, ask the system administrator to indicate how the system takes appropriate action when an audit storage volume is full. If there is no evidence of appropriate action, this is a finding.)
  desc 'fix', 'Apply the machine config by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 70-auditd-conf-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,%23%0A%23%20This%20file%20controls%20the%20configuration%20of%20the%20audit%20daemon%0A%23%0A%0Alocal_events%20%3D%20yes%0Awrite_logs%20%3D%20yes%0Alog_file%20%3D%20%2Fvar%2Flog%2Faudit%2Faudit.log%0Alog_group%20%3D%20root%0Alog_format%20%3D%20ENRICHED%0Aflush%20%3D%20incremental_async%0Afreq%20%3D%2050%0Amax_log_file%20%3D%206%0Anum_logs%20%3D%205%0Apriority_boost%20%3D%204%0Aname_format%20%3D%20hostname%0A%23%23name%20%3D%20mydomain%0Amax_log_file_action%20%3D%20syslog%0Aspace_left%20%3D%2025%25%0Aspace_left_action%20%3D%20syslog%0Averify_email%20%3D%20yes%0Aaction_mail_acct%20%3D%20root%0Aadmin_space_left%20%3D%2050%0Aadmin_space_left_action%20%3D%20syslog%0Adisk_full_action%20%3D%20HALT%0Adisk_error_action%20%3D%20HALT%0Ause_libwrap%20%3D%20yes%0A%23%23tcp_listen_port%20%3D%2060%0Atcp_listen_queue%20%3D%205%0Atcp_max_per_addr%20%3D%201%0A%23%23tcp_client_ports%20%3D%201024-65535%0Atcp_client_max_idle%20%3D%200%0Atransport%20%3D%20TCP%0Akrb5_principal%20%3D%20auditd%0A%23%23krb5_key_file%20%3D%20%2Fetc%2Faudit%2Faudit.key%0Adistribute_network%20%3D%20no%0Aq_depth%20%3D%20400%0Aoverflow_action%20%3D%20syslog%0Amax_restarts%20%3D%2010%0Aplugin_dir%20%3D%20%2Fetc%2Faudit%2Fplugins.d%0A
        mode: 0640
        path: /etc/audit/auditd.conf
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61256r921504_chk'
  tag severity: 'medium'
  tag gid: 'V-257521'
  tag rid: 'SV-257521r921506_rule'
  tag stig_id: 'CNTR-OS-000190'
  tag gtitle: 'SRG-APP-000096-CTR-000175'
  tag fix_id: 'F-61180r921505_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
