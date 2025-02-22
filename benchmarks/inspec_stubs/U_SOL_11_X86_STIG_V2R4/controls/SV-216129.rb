control 'SV-216129' do
  title 'The operating system must prevent remote devices that have established a non-remote connection with the system from communicating outside of the communication path with resources in external networks.'
  desc 'This control enhancement is implemented within the remote device (e.g., notebook/laptop computer) via configuration settings not configurable by the user of the device. An example of a non-remote communications path from a remote device is a virtual private network. When a non-remote connection is established using a virtual private network, the configuration settings prevent split-tunneling. Split-tunneling might otherwise be used by remote users to communicate with the information system as an extension of the system and to communicate with local resources, such as a printer or file server. The remote device, when connected by a non-remote connection, becomes an extension of the information system allowing dual communications paths, such as split-tunneling, in effect allowing unauthorized external connections into the system. This is a split-tunneling requirement that can be controlled via the operating system by disabling interfaces.'
  desc 'check', 'Determine if the "RestrictOutbound" profile is configured properly:

# profiles -p RestrictOutbound info

If the output is not:
name=RestrictOutbound
desc=Restrict Outbound Connections
limitpriv=zone,!net_access

this is a finding.


For users who are not allowed external network access, determine if a user is configured with the "RestrictOutbound" profile.

# profiles -l [username]

If the output does not include:

[username]:
RestrictOutbound

this is a finding.'
  desc 'fix', 'The root Role is required.

Remove net_access privilege from users who may be accessing the systems externally.

1. Create an RBAC Profile with net_access restriction

# profiles -p RestrictOutbound
profiles:RestrictOutbound> set desc="Restrict Outbound Connections"
profiles:RestrictOutbound> set limitpriv=zone,!net_access
profiles:RestrictOutbound> exit


2. Assign the RBAC Profile to a user

# usermod -P +RestrictOutbound [username]

This prevents the user from initiating any outbound network connections.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17367r372769_chk'
  tag severity: 'medium'
  tag gid: 'V-216129'
  tag rid: 'SV-216129r603268_rule'
  tag stig_id: 'SOL-11.1-040490'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17365r372770_fix'
  tag 'documentable'
  tag legacy: ['SV-61019', 'V-48147']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
