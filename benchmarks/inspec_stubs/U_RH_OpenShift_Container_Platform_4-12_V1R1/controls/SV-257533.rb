control 'SV-257533' do
  title 'OpenShift must protect audit information from unauthorized modification.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult if not impossible to achieve. In addition, access to audit records provides information an attacker could potentially use to his or her advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records must not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

'
  desc 'check', %q(Verify the audit system prevents unauthorized changes by executing the following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n ""$HOSTNAME ""; grep "^\-e\s2\s*$" /etc/audit/audit.rules /etc/audit/rules.d/*  || echo "not found"' 2>/dev/null; done

If the check returns "not found", the audit system is not set to be immutable by adding the ""-e 2"" option to the ""/etc/audit/audit.rules"", this is a finding.)
  desc 'fix', 'Apply the machine config to prevent unauthorized changes by executing the following:

for mcpool in $(oc get mcp -oname | sed "s:.*/::" ); do
echo "apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  name: 90-immutable-rules-$mcpool
  labels:
    machineconfiguration.openshift.io/role: $mcpool
spec:
  config:
    ignition:
      version: 3.1.0
    storage:
      files:
      - contents:
          source: data:,-e%202%0A
        mode: 0600
        path: /etc/audit/rules.d/90-immutable.rules
        overwrite: true
" | oc apply -f -
done'
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61268r921540_chk'
  tag severity: 'medium'
  tag gid: 'V-257533'
  tag rid: 'SV-257533r921542_rule'
  tag stig_id: 'CNTR-OS-000310'
  tag gtitle: 'SRG-APP-000119-CTR-000245'
  tag fix_id: 'F-61192r921541_fix'
  tag satisfies: ['SRG-APP-000119-CTR-000245', 'SRG-APP-000120-CTR-000250']
  tag 'documentable'
  tag cci: ['CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a']
end
