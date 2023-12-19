control 'SV-257531' do
  title 'OpenShift must protect log directory from any type of unauthorized access by setting owner permissions.'
  desc 'OpenShift follows the principle of least privilege, which aims to restrict access to resources based on user roles and responsibilities. This separation of privileges helps mitigate the risk of unauthorized modifications or unauthorized access by users or processes that do not need to interact with the file.

Protecting the /var/log directory from unauthorized access helps safeguard against potential security threats. Unauthorized users gaining access to the file may exploit vulnerabilities, tamper with logs, or extract sensitive information. By setting strict file owner permissions, OpenShift minimizes the risk of unauthorized individuals or processes accessing or modifying the directory, reducing the likelihood of security breaches.'
  desc 'check', %q(Verify the "/var/log" directory is group-owned by root by executing the following command:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; stat -c "%G" /var/log' 2>/dev/null; done

If "root" is not returned as a result, this is a finding.)
  desc 'fix', %q(Correct log directory ownership by executing the following:

 for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; chown root:root /var/log/' 2>/dev/null; done)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61266r921534_chk'
  tag severity: 'medium'
  tag gid: 'V-257531'
  tag rid: 'SV-257531r921536_rule'
  tag stig_id: 'CNTR-OS-000290'
  tag gtitle: 'SRG-APP-000118-CTR-000240'
  tag fix_id: 'F-61190r921535_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
