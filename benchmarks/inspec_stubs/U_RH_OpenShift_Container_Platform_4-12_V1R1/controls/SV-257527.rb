control 'SV-257527' do
  title 'OpenShift must protect audit logs from any type of unauthorized access.'
  desc 'If audit data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve. In addition, access to audit records provides information an attacker could potentially use to their advantage.

To ensure the veracity of audit data, the information system and/or the application must protect audit information from all unauthorized access. This includes read, write, and copy access.

This requirement can be achieved through multiple methods, which will depend upon system architecture and design. Commonly employed methods for protecting audit information include least privilege permissions as well as restricting the location and number of log file repositories.

Additionally, applications with user interfaces to audit records must not allow for the unfettered manipulation of or access to those records via the application. If the application provides access to the audit data, the application becomes accountable for ensuring audit information is protected from unauthorized access.

Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.'
  desc 'check', %q(Verify the audit logs have a mode of "0600" by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; stat -c "%a %n" /var/log/audit/audit.log' 2>/dev/null; done

(Sample Output: 600 /var/log/audit/audit.log)
If the audit log has a mode more permissive than "0600", this is a finding.

Determine if the audit log is owned by "root" executing the following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; ls -l /var/log/audit/audit.log' 2>/dev/null; done

(Sample Output: rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log)
If the audit log is not owned by "root", this is a finding.

Verify the audit log directory is group-owned by "root" to prevent unauthorized read access by executing the following.

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; ls -ld /var/log/audit' 2>/dev/null; done

(Sample Output: drw------- 2 root root 23 Jun 11 11:56 /var/log/audit)
If the audit log directory is not group-owned by "root", this is a finding.

Verify the audit log directories have a mode of "0700" by executing the following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; stat -c "%a %n" /var/log/audit' 2>/dev/null; done

(Sample Output: 700 /var/log/audit)
If the audit log directory has a mode more permissive than "0700", this is a finding.)
  desc 'fix', %q(Correct permissions (audit logs have a mode of "0600") by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); chmod 600 /var/log/audit/audit.log' 2>/dev/null; done

Correct permissions (audit log is owned by "root") by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); chown root:root /var/log/audit/audit.log' 2>/dev/null; done

Correct permissions (audit log directory is group-owned by "root") by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); chown root:root /var/log/audit' 2>/dev/null; done

Correct permissions ( audit log directories have a mode of "0700") by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); chmod 700 /var/log/audit' 2>/dev/null; done)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61262r921522_chk'
  tag severity: 'medium'
  tag gid: 'V-257527'
  tag rid: 'SV-257527r921524_rule'
  tag stig_id: 'CNTR-OS-000250'
  tag gtitle: 'SRG-APP-000118-CTR-000240'
  tag fix_id: 'F-61186r921523_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
