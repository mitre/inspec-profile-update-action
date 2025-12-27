control 'SV-6998' do
  title 'An IS has its BIOS set to allow a boot from a USB device.'
  desc "If an IS's BIOS is left set to allow it to be booted from a USB device, an individual can plug a USB device into the IS and force a reboot, either performing a hardware reset or cycling the power.  This can lead to a denial of service.  Additionally this can lead to the compromise of sensitive data on the IS that was rebooted and possibly to the network the IS is attached."
  desc 'check', 'The reviewer will interview the IAO or SA to verify that no IS has its BIOS set to allow a boot from any USB device.   Note an IS can be booted from a USB device for maintenance or recovery purposes, but will never be allowed to do so when in normal use.
Note: Some systems do not have a setting for disabling Boot from USB. In these cases, boot from USB should be moved to last in the boot device list in the bios. The risk is lessened not mitigated so the reviewer will mark this as a CAT 2 finding.'
  desc 'fix', "Develop a plan to check all ISs' BIOS settings as soon a possible.  The check will verify that none of the BIOS are set to allow a boot from a USB device.  Obtain CM approval for the plan and execute the plan."
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2939r1_chk'
  tag severity: 'high'
  tag gid: 'V-6776'
  tag rid: 'SV-6998r1_rule'
  tag stig_id: 'USB02.011.00'
  tag gtitle: 'An IS BIOS is Set to Allow Boot from USB'
  tag fix_id: 'F-6429r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'DCBP-1'
end
