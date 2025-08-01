control 'SV-257530' do
  title 'OpenShift must protect log directory from any type of unauthorized access by setting file permissions.'
  desc 'Log files contain sensitive information such as user credentials, system configurations, and potentially even security-related events. Unauthorized access to log files can expose this sensitive data to malicious actors. By protecting the log directory, OpenShift ensures that only authorized users or processes can access the log files, preserving the confidentiality of the information contained within them.'
  desc 'check', %q(Verify the "/var/log" directory has a mode of "0755" or less by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; stat -c "%a %n" /var/log' 2>/dev/null; done

If a value of "0755" or less permissive is not returned, this is a finding.)
  desc 'fix', %q(Correct log directory permissions by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; chmod 755 /var/log/' 2>/dev/null; done)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61265r921531_chk'
  tag severity: 'medium'
  tag gid: 'V-257530'
  tag rid: 'SV-257530r921533_rule'
  tag stig_id: 'CNTR-OS-000280'
  tag gtitle: 'SRG-APP-000118-CTR-000240'
  tag fix_id: 'F-61189r921532_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
