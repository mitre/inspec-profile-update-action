control 'SV-6986' do
  title 'There is no document instructing users that USB devices be powered off for at least 60 seconds prior to being connected to an IS.'
  desc 'Because USB devices that contain only volatile memory are designed to withstand minor fluctuations in power they contain some means of maintaining memory for short power interruptions.  Users need to ensure that USB devices remain without power for at least 60 seconds when disconnecting them from one IS, and connecting to a different IS to make sure enough time passes for all power to dissipate and the memory erased.
The IAO will ensure that the SFUG or an equivalent document requires that all USB devices be powered off for at least 60 seconds prior to being connected to an IS.'
  desc 'check', 'The reviewer will interview the IAO and view the SFUG, or equivalent documentation, to verify that it is documented that users should remove all power from a USB device when it is moved from one IS to another for at least 60 seconds to allow all power to dissipate and the memory to erase.'
  desc 'fix', 'Update the SFUG, or an equivalent document, to include this information.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2911r1_chk'
  tag severity: 'low'
  tag gid: 'V-6764'
  tag rid: 'SV-6986r1_rule'
  tag stig_id: 'USB00.001.00'
  tag gtitle: 'USB Poweroff Directive in SFUG'
  tag fix_id: 'F-6417r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
