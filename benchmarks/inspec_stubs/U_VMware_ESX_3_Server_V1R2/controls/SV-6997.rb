control 'SV-6997' do
  title 'The USB usage section of the SFUG, or equivalent document, does not contain a discussion of the devices that contain persistent non-removable memory.'
  desc 'Without a discussion of tthe devices that contain persistent non-removable memory, an uninformed user can mistakenly attach such a device to an IS leading to the denial of service caused by an infection of the IS and possibly the network with malicious code.  Additionally the user might compromise sensitive data thinking that removal of a memory card removed all the persistent memory within a device.
The IAO will ensure that the USB usage section of the SFUG contains a discussion of the devices that contain persistent non-removable memory.'
  desc 'check', 'The reviewer will interview the IAO and review the relevant documentation.  The discussion should point out that with some devices it may not be obvious that it contains persistent non-removable memory and that, if there is a doubt, it will be treated as if it contains persistent memory.'
  desc 'fix', 'Develop, update, and distribute a SFUG section on USB devices that discusses devices that may contain persistent non-removable memory in accordance with the SPAN STIG.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2937r1_chk'
  tag severity: 'low'
  tag gid: 'V-6775'
  tag rid: 'SV-6997r1_rule'
  tag stig_id: 'USB01.010.00'
  tag gtitle: 'USB SFUG Persistent Non-Removable Memory'
  tag fix_id: 'F-6428r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'PRRB-1'
end
