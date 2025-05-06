control 'SV-235809' do
  title 'Docker Enterprise host devices must not be directly exposed to containers.'
  desc 'Host devices can be directly exposed to containers at runtime. Do not directly expose host devices to containers especially for containers that are not trusted.

The --device option exposes the host devices to the containers and consequently, the containers can directly access such host devices. Do not require the container to run in privileged mode to access and manipulate the host devices. By default, the container will be able to read, write and mknod these devices. Additionally, it is possible for containers to remove block devices from the host. Hence, do not expose host devices to containers directly.

If at all, expose the host device to a container, use the sharing permissions appropriately:

r - read only
w - writable
m - mknod allowed

The user would not be able to use the host devices directly within the containers.

By default, no host devices are exposed to containers. If the user does not provide sharing permissions and choose to expose a host device to a container, the host device would be exposed with read, write, and mknod permissions.'
  desc 'check', "Ensure host devices are not directly exposed to containers. Verify that the host device needs to be accessed from within the container and the permissions required are correctly set.

This check should be executed on all nodes in a Docker Enterprise cluster.

via CLI:

Linux: As a Docker EE Admin, execute the following command using a Universal Control Plane (UCP) client bundle:

docker ps --quiet --all | xargs docker inspect --format '{{ .Id }}: Devices={{ .HostConfig.Devices }}'

The above command lists out each device with below information:

- CgroupPermissions - For example, rwm
- PathInContainer - Device path within the container
- PathOnHost - Device path on the host

If Devices=[], or Devices=<no value>, this is not a finding. If Devices are listed and the host device is not documented and approved in the System Security Plan (SSP), this is a finding."
  desc 'fix', 'Do not directly expose the host devices to containers. If at all, expose the host devices to containers, use the correct set of permissions:

For example, do not start a container as below:

docker run --interactive --tty --device=/dev/tty0:/dev/tty0:rwm --device=/dev/temp_sda:/dev/temp_sda:rwm centos bash

For example, share the host device with correct permissions:

docker run --interactive --tty --device=/dev/tty0:/dev/tty0:rw --device=/dev/temp_sda:/dev/temp_sda:r centos bash'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39028r627552_chk'
  tag severity: 'high'
  tag gid: 'V-235809'
  tag rid: 'SV-235809r627554_rule'
  tag stig_id: 'DKER-EE-002040'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-38991r627553_fix'
  tag 'documentable'
  tag legacy: ['SV-104791', 'V-95653']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
