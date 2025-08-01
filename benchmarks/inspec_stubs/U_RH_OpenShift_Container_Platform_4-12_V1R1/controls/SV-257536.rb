control 'SV-257536' do
  title 'OpenShift must use FIPS-validated cryptographic mechanisms to protect the integrity of log information.'
  desc 'To fully investigate an incident and to have trust in the audit data that is generated, it is important to put in place data protections. Without integrity protections, unauthorized changes may be made to the audit files and reliable forensic analysis and discovery of the source of malicious system activity may be degraded. Although digital signatures are one example of protecting integrity, this control is not intended to cause a new cryptographic hash to be generated every time a record is added to a log file. 

Integrity protections can also be implemented by using cryptographic techniques for security function isolation and file system protections to protect against unauthorized changes.'
  desc 'check', 'Verify the Cluster Log Forwarder is using an encrypted transport by executing the following:

oc get clusterlogforwarder -n openshift-logging

For each Cluster Log Forwarder, run the following command to display the configuration.

oc describe clusterlogforwarder <name> -n openshift-logging

Review the configuration and determine if the transport is secure, such as tls:// or https://. If there are any transports configured that are not secured by TLS, this is a finding.'
  desc 'fix', 'Edit the Cluster Log Forwarder configuration to configure TLS on the transport by executing the following:

oc edit clusterlogforwarder <name> -n openshift-logging

For any output->url value that is not using a secure transport, edit the url to use a secure (https:// or tls://) transport.

For detailed information regarding configuration of the Cluster Log Forwarder, refer to https://docs.openshift.com/container-platform/4.8/logging/cluster-logging-external.html.'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61271r921549_chk'
  tag severity: 'medium'
  tag gid: 'V-257536'
  tag rid: 'SV-257536r921551_rule'
  tag stig_id: 'CNTR-OS-000340'
  tag gtitle: 'SRG-APP-000126-CTR-000275'
  tag fix_id: 'F-61195r921550_fix'
  tag 'documentable'
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
end
