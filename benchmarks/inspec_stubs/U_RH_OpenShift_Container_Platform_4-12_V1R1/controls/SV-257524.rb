control 'SV-257524' do
  title 'OpenShift components must provide the ability to send audit logs to a central enterprise repository for review and analysis.'
  desc 'Sending audit logs to a central enterprise repository allows for centralized log management. Instead of scattered logs across multiple OpenShift components, having a centralized repository simplifies log storage, retention, and retrieval. It provides a single source of truth for audit logs, making it easier to manage and analyze log data.

Centralized audit logs are crucial for incident response and forensic investigations. When a security incident occurs, having audit logs in a central repository allows security teams to quickly access relevant log data for analysis. It facilitates incident reconstruction, root cause analysis, and the identification of the scope and impact of the incident. This is vital for effective incident response and minimizing the impact of security breaches.

'
  desc 'check', "Determine if cluster log forwarding is configured.

1. Verify the cluster-logging operator is installed by executing the following:

oc get subscription/cluster-logging -n openshift-logging
(Example Output:
NAME              PACKAGE           SOURCE             CHANNEL
cluster-logging   cluster-logging   redhat-operators   stable
)

If the cluster-logging operator is not present, this is a finding.

2. List the cluster log forwarders defined by executing the following:

oc get clusterlogforwarder -n openshift-logging

If there are no clusterlogforwarders defined, this is a finding.

3. For each cluster log forwarder listed above, view the configuration details by executing the following:
 
oc describe clusterlogforwarder/<CLF_NAME> -n openshift-logging

Review the details of the cluster log forwarder.

If the configuration is not set to forward logs the organization's centralized logging service, this is a finding."
  desc 'fix', %q(To configure log forwarding, the OpenShift Cluster Logging operator first must be installed, and then the Cluster Log Forwarder is configured to forward logs to a centralized log aggregation service.

To install the OpenShift Cluster Logging operator, execute the following command to apply the subscription manifests to the cluster:

oc apply -f - << 'EOF'
---
apiVersion: project.openshift.io/v1
kind: Project
metadata:
  labels:
    kubernetes.io/metadata.name: openshift-logging
    openshift.io/cluster-monitoring: "true"
  name: openshift-logging
spec: {}
...
---
apiVersion: operators.coreos.com/v1
kind: OperatorGroup
metadata:
  name: openshift-logging
  namespace: openshift-logging
spec:
  targetNamespaces:
  - openshift-logging
...
---
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/cluster-logging.openshift-logging: ""
  name: cluster-logging
  namespace: openshift-logging
spec:
  channel: stable
  installPlanApproval: Automatic
  name: cluster-logging
  source: redhat-operators
  sourceNamespace: openshift-marketplace
...
EOF

After the OpenShift Logging operator has finished installing, a ClusterLogForwarder instance can be created to forward cluster logs to a log aggregator. A basic configuration that would forward OpenShift audit, application, and infrastructure logs to an rsyslog server that is managed separately and is configured for mTLS authentication over TCP when sending audit logs, but traditional UDP access for other types of logs, can be provided by editing the appropriate values in the Secret resource below and changing the "url" parameters in the "outputs" section of the "spec" below, then running the command to apply (Example):

oc apply -f - << 'EOF'
---
apiVersion: v1
kind: Secret
metadata:
  name: rsyslog-tls-secret
  namespace: openshift-logging
data:
  tls.crt: <base64 encoded client certificate>
  tls.key: <base64 encoded client key>
  ca-bundle.crt: <base64 encoded CA bundle that signed the certificate of your rsyslog server>
...
---
apiVersion: logging.openshift.io/v1
kind: ClusterLogForwarder
metadata:
  name: instance
  namespace: openshift-logging
spec:
  outputs:
   - name: rsyslog-audit
     type: syslog
     syslog:
       facility: security
       rfc: RFC5424
       severity: Informational
       appName: openshift
       msgID: audit
       procID: audit
     url: 'tls://rsyslogserver.example.com:514'
     secret:
       name: rsyslog-tls-secret
   - name: rsyslog-apps
     type: syslog
     syslog:
       facility: user
       rfc: RFC5424
       severity: Informational
       appName: openshift
       msgID: apps
       procID: apps
     url: 'udp://rsyslogserver.example.com:514'
   - name: rsyslog-infra
     type: syslog
     syslog:
       facility: local0
       rfc: RFC5424
       severity: Informational
       appName: openshift
       msgID: infra
       procID: infra
     url: 'udp://rsyslogserver.example.com:514'
  pipelines:
   - name: audit-logs
     inputRefs:
      - audit
     outputRefs:
      - rsyslog-audit
   - name: apps-logs
     inputRefs:
      - application
     outputRefs:
      - rsyslog-apps
   - name: infrastructure-logs
     inputRefs:
      - infrastructure
     outputRefs:
      - rsyslog-infra
...
EOF

Note that many log forwarding destinations are supported, and the fix does not require that users forward audit logs to rsyslog over mTLS. To better understand how to configure the ClusterLogForwarder, consult the OpenShift Logging documentation:
https://docs.openshift.com/container-platform/4.8/logging/cluster-logging-external.html)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61259r921513_chk'
  tag severity: 'medium'
  tag gid: 'V-257524'
  tag rid: 'SV-257524r921515_rule'
  tag stig_id: 'CNTR-OS-000220'
  tag gtitle: 'SRG-APP-000111-CTR-000220'
  tag fix_id: 'F-61183r921514_fix'
  tag satisfies: ['SRG-APP-000111-CTR-000220', 'SRG-APP-000092-CTR-000165', 'SRG-APP-000358-CTR-000805']
  tag 'documentable'
  tag cci: ['CCI-000154', 'CCI-001464', 'CCI-001851']
  tag nist: ['AU-6 (4)', 'AU-14 (1)', 'AU-4 (1)']
end
