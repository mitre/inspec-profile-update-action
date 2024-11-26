control 'SV-207674' do
  title 'The ESXi host must use DoD-approved certificates.'
  desc 'The default self-signed, VMCA issued host certificate must be replaced with a DoD-approved certificate. The use of a DoD certificate on the host assures clients that the service they are connecting to is legitimate and properly secured.'
  desc 'check', 'Temporarily enable SSH, connect to the ESXi host and run the following command:

# openssl x509 -in /etc/vmware/ssl/rui.crt -text | grep Issuer

If the issuer is not a DoD approved certificate authority, or other AO approved certificate authority, this is a finding.'
  desc 'fix', 'Obtain a DoD issued certificate and private key for the host following the below requirements:

Key size: 2048 bits or more (PEM encoded)
Key format: PEM. VMware supports PKCS8 and PKCS1 (RSA keys)
x509 version 3
SubjectAltName must contain DNS Name=<machine_FQDN>
CRT (Base-64) format
Contains the following Key Usages: Digital Signature, Non Repudiation, Key Encipherment
Start time of one day before the current time
CN (and SubjectAltName) set to the host name (or IP address) that the ESXi host has in the vCenter Server inventory.

Put the host into maintenance mode.

Temporarily enable SSH on the host. SCP the new certificate and key to /tmp. SSH to the host. Back up the existing certificate and key:

mv /etc/vmware/ssl/rui.crt /etc/vmware/ssl/rui.crt.bak
mv /etc/vmware/ssl/rui.key /etc/vmware/ssl/rui.key.bak

Copy your new certificate and key to /etc/vmware/ssl/ and rename them to rui.crt and rui.key respectively. Restart management agents to implement the new certificate:

services.sh restart

From the vSphere Web Client go to vCenter Inventory Lists >> vCenter Servers >> Select your vCenter Server >> Manage >> Settings >> Advanced Settings. Find or create the vpxd.certmgmt.mode key and set its value to custom.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7929r622444_chk'
  tag severity: 'medium'
  tag gid: 'V-207674'
  tag rid: 'SV-207674r617349_rule'
  tag stig_id: 'ESXI-65-000078'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7929r364422_fix'
  tag 'documentable'
  tag legacy: ['SV-104319', 'V-94489']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
