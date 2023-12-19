control 'SV-254563' do
  title 'All audit records must identify any containers associated with the event within Rancher RKE2.'
  desc 'Ensure that the --audit-log-maxage argument is set to 30 or as appropriate.

Retaining logs for at least 30 days ensures that you can go back in time and investigate or correlate any events. Set your audit log retention period to 30 days or as per your business requirements.
Result: Pass'
  desc 'check', 'Ensure audit-log-maxage is set correctly.

Run the below command on the RKE2 Control Plane:
/bin/ps -ef | grep kube-apiserver | grep -v grep

If --audit-log-maxage argument is not set to at least 30 or is not configured, this is a finding. 
(By default, RKE2 sets the --audit-log-maxage argument parameter to 30.)'
  desc 'fix', 'Edit the RKE2 Configuration File /etc/rancher/rke2/config.yaml on the RKE2 Control Plane and set the following "kube-apiserver-arg" argument:

- audit-log-maxage=30

Once the configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58047r859257_chk'
  tag severity: 'medium'
  tag gid: 'V-254563'
  tag rid: 'SV-254563r918257_rule'
  tag stig_id: 'CNTR-R2-000320'
  tag gtitle: 'SRG-APP-000100-CTR-000200'
  tag fix_id: 'F-57996r918237_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
