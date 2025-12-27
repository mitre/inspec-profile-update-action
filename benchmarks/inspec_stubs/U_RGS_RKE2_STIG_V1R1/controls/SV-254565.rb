control 'SV-254565' do
  title 'Rancher RKE2 must be configured with only essential configurations.'
  desc 'It is important to disable any unnecessary components to reduce any potential attack surfaces. 

RKE2 allows disabling the following components:
- rke2-canal
- rke2-coredns
- rke2-ingress-nginx
- rke2-kube-proxy
- rke2-metrics-server

If utilizing any of these components presents a security risk, or if any of the components are not required then they can be disabled by using the "disable" flag.

If any of the components are not required, they can be disabled by using the "disable" flag.

'
  desc 'check', 'Ensure the RKE2 Server configuration file on all RKE2 Server hosts contain a "disable" flag for all unnecessary components. 

Run this command on the RKE2 Control Plane:
cat /etc/rancher/rke2/config.yaml

RKE2 allows disabling the following components. If any of the components are not required, they can be disabled:
- rke2-canal
- rke2-coredns
- rke2-ingress-nginx
- rke2-kube-proxy
- rke2-metrics-server

If services not in use are enabled, this is a finding.'
  desc 'fix', 'Disable unnecessary RKE2 components.
Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc/rancher/rke2/config.yaml, so that it contains a "disable" flag for all unnecessary components. 

Example:
disable: rke2-canal
disable: rke2-coredns
disable: rke2-ingress-nginx
disable: rke2-kube-proxy
disable: rke2-metrics-server

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58049r859263_chk'
  tag severity: 'medium'
  tag gid: 'V-254565'
  tag rid: 'SV-254565r859265_rule'
  tag stig_id: 'CNTR-R2-000550'
  tag gtitle: 'SRG-APP-000141-CTR-000315'
  tag fix_id: 'F-57998r859264_fix'
  tag satisfies: ['SRG-APP-000141-CTR-000315', 'SRG-APP-000384-CTR-000915']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001764']
  tag nist: ['CM-7 a', 'CM-7 (2)']
end
