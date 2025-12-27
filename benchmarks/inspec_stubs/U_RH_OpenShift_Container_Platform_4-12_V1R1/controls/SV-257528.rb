control 'SV-257528' do
  title 'OpenShift must protect system journal file from any type of unauthorized access by setting file permissions.'
  desc 'It is a fundamental security practice to enforce the principle of least privilege, where only the necessary permissions are granted to authorized entities. OpenShift must protect the system journal file from any type of unauthorized access by setting file permissions. 

The system journal file contains important log data that helps in troubleshooting and monitoring the system. Unauthorized access or tampering with the journal file can compromise the integrity of this data. By setting appropriate file permissions, OpenShift ensures that only authorized users or processes have access to the journal file, maintaining the integrity and reliability of system logs.'
  desc 'check', %q(Verify the system journal file has mode "0640" or less permissive by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); stat -c "%a %n" /var/log/journal/$machine_id/system.journal' 2>/dev/null; done

If a value of "0640" or less permissive is not returned, this is a finding.)
  desc 'fix', %q(Correct journal file permissions by executing the following:

for node in $(oc get node -oname); do oc debug $node -- chroot /host /bin/bash -c 'echo -n "$HOSTNAME "; machine_id=$(systemd-machine-id-setup --print); chmod 640 /var/log/journal/$machine_id/system.journal' 2>/dev/null; done)
  impact 0.5
  ref 'DPMS Target Red Hat OpenShift Container Platform 4.12'
  tag check_id: 'C-61263r921525_chk'
  tag severity: 'medium'
  tag gid: 'V-257528'
  tag rid: 'SV-257528r921527_rule'
  tag stig_id: 'CNTR-OS-000260'
  tag gtitle: 'SRG-APP-000118-CTR-000240'
  tag fix_id: 'F-61187r921526_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
