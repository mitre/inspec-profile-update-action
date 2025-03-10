control 'SV-254573' do
  title 'Rancher RKE2 keystore must implement encryption to prevent unauthorized disclosure of information at rest within Rancher RKE2.'
  desc 'Encrypting secrets at rest in etcd.

By default, RKE2 will create an encryption key and configuration file and pass these to the Kubernetes API server. The result is that RKE2 automatically encrypts Kubernetes Secret objects when writing them to etcd.'
  desc 'check', 'Review the encryption configuration file.

As root or with root permissions, run the following command:
view /var/lib/rancher/rke2/server/cred/encryption-config.json

Ensure the RKE2 configuration file on all RKE2 servers, located at /etc/rancher/rke2/config.yaml, does NOT contain:

secrets-encryption: false

If secrets encryption is turned off, this is a finding.'
  desc 'fix', 'Enable secrets encryption.

Edit the RKE2 configuration file on all RKE2 servers, located at /etc/rancher/rke2/config.yaml, so that it does NOT contain:

secrets-encryption: false

or that secrets-encryption is set to true.'
  impact 0.5
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58057r859287_chk'
  tag severity: 'medium'
  tag gid: 'V-254573'
  tag rid: 'SV-254573r879800_rule'
  tag stig_id: 'CNTR-R2-001500'
  tag gtitle: 'SRG-APP-000429-CTR-001060'
  tag fix_id: 'F-58006r859288_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
