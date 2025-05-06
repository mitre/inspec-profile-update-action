control 'SV-257523' do
  title 'OpenShift must take appropriate action upon an audit failure.'
  desc 'It is critical that when the container platform is at risk of failing to process audit logs as required that it takes action to mitigate the failure. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

Because availability of the services provided by the container platform, approved actions in response to an audit failure are as follows:

(i) If the failure was caused by the lack of audit record storage capacity, the container platform must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the container platform must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action must be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify there is a Prometheus rule to watch for audit events by executing the following:

oc get prometheusrule -o yaml --all-namespaces | grep apiserver_audit

Output:
         sum by (apiserver,instance)(rate(apiserver_audit_error_total{apiserver=~".+-apiserver"}[5m])) / sum by (apiserver,instance) (rate(apiserver_audit_event_total{apiserver=~".+-apiserver"}[5m])) > 0

If the output above is not displayed, this is a finding.'
  desc 'fix', %q(Apply the following Prometheus rule by executing the following:

oc apply -f - << 'EOF'
---
# platform = multi_platform_ocp
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: audit-errors
  namespace: openshift-kube-apiserver
spec:
  groups:
  - name: apiserver-audit
    rules:
    - alert: AuditLogError
      annotations:
        summary: |-
          An API Server instance was unable to write audit logs. This could be
          triggered by the node running out of space, or a malicious actor
          tampering with the audit logs.
        description: An API Server had an error writing to an audit log.
      expr: |
        sum by (apiserver,instance)(rate(apiserver_audit_error_total{apiserver=~".+-apiserver"}[5m])) / sum by (apiserver,instance) (rate(apiserver_audit_event_total{apiserver=~".+-apiserver"}[5m])) > 0
      for: 1m
      labels:
        severity: warning
EOF)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61258r921510_chk'
  tag severity: 'medium'
  tag gid: 'V-257523'
  tag rid: 'SV-257523r921512_rule'
  tag stig_id: 'CNTR-OS-000210'
  tag gtitle: 'SRG-APP-000109-CTR-000215'
  tag fix_id: 'F-61182r921511_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
