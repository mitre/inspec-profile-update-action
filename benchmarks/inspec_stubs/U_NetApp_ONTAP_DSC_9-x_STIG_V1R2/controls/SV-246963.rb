control 'SV-246963' do
  title 'ONTAP must be configured to use a data authentication key to safeguard against denial-of-service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

Usually, DoS attacks are assumed to be network related where the attacker floods the network with traffic that causes legitimate network traffic to be either slowed or blocked. For a storage device, a DoS attack can also occur when an attacker is able to make the data on the disks unreadable, thus unavailable, to the customer. This is a common attack used by ransomware where the attacker encrypts the data on the drives requesting payment for the unencryption key. By using data authentication keys, an attacker is unable to read or write data to the drives. It is also important to make sure the mode of the drives is set to full, otherwise only some of the data on the drive is protected.'
  desc 'check', 'Validate that a data authentication key has been assigned using the command "storage encryption disk show".

If any of the disks has a mode other than "full" or the Data Key ID is missing, this is a finding.'
  desc 'fix', 'Configure ONTAP to use a data authentication key for access with the command "storage encryption disk modify -disk <disk_ID> -data-key-id <key-ID>" where disk_ID is the disk and key_ID is the data authentication key. 

To verify the key is set, use the command "storage encryption disk show -disk <disk_ID>". The command will show the data mode. The mode must be set to full.

If the mode is not set to full, use the command "disk modify -disk <disk_ID> -protection-mode full" to set the mode to full.  Validate the mode changed using the command "storage encryption disk show -disk <disk_ID>".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50395r835275_chk'
  tag severity: 'medium'
  tag gid: 'V-246963'
  tag rid: 'SV-246963r835277_rule'
  tag stig_id: 'NAOT-SC-000005'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-50349r835276_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
