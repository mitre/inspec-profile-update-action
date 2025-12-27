control 'SV-257529' do
  title 'OpenShift must protect system journal file from any type of unauthorized access by setting owner permissions.'
  desc 'OpenShift follows the principle of least privilege, which aims to restrict access to resources based on user roles and responsibilities. This separation of privileges helps mitigate the risk of unauthorized modifications or unauthorized access by users or processes that do not need to interact with the file.

Protecting the system journal file from unauthorized access helps safeguard against potential security threats. The system journal file contains critical log data that is vital for system analysis, troubleshooting, and security auditing. Unauthorized users gaining access to the file may exploit vulnerabilities, tamper with logs, or extract sensitive information. By setting strict file owner permissions, OpenShift minimizes the risk of unauthorized individuals or processes accessing or modifying the journal file, reducing the likelihood of security breaches.'
  desc 'check', %q(Verify the "system journal" file is group-owned by systemd-journal and owned by root by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); stat -c "%U %G" /var/log/journal/$machine_id/system.journal' 2>/dev/null; done

Example output:
ip-10-0-150-1 root systemd-journal

If "root" is not returned as the owner, this is a finding.

If "systemd-journald" is not returned as the group owner, this is a finding.)
  desc 'fix', %q(Correct journal file ownership by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); chown root:systemd-journal /var/log/journal/$machine_id/system.journal' 2>/dev/null; done)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61264r921528_chk'
  tag severity: 'medium'
  tag gid: 'V-257529'
  tag rid: 'SV-257529r921530_rule'
  tag stig_id: 'CNTR-OS-000270'
  tag gtitle: 'SRG-APP-000118-CTR-000240'
  tag fix_id: 'F-61188r921529_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
