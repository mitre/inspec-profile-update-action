control 'SV-55748' do
  title 'IP-based VTC systems implementing a single CODEC supporting conferences on multiple networks having different classification levels must sanitize non-volatile memory while transitioning between networks by overwriting all configurable parameters with null settings before reconfiguring the CODEC for connection to the next network.'
  desc 'A factory reset is the software restore of an electronic device to its original system state by erasing all of the information stored on the device to restore the device to its original factory or unconfigured settings. This erases all of the data, settings, and applications that were previously on the device. Factory reset may be used as part of the sanitization process.

This requirement is satisfied by the use of either a properly configured automated configuration management system or by the use of an inherent sanitization capability of the unit. However, this requirement results in a CAT III finding if a manual procedure is used.'
  desc 'check', 'Verify that the VTC system has an automated configuration management system configured to sanitize and reconfigure the CODEC when transitioning between networks. If it does, review documentation to determine that this capability is being implemented. If these conditions are met, this is not a finding. 
If the unit is not implementing an automated process, review documentation to determine whether a manual procedure is specified and implemented when transitioning between networks; this will result in a CAT III finding if these conditions are met and a CAT II finding if they are not.
If an automatic capability exists but is not being implemented or an automated configuration management system is not being used, this is a CAT II finding unless a manual procedure is specified and is being implemented, then this is a CAT III finding.
If the unit is not being sanitized when transitioning between networks, this is a CAT II finding.'
  desc 'fix', 'Obtain a VTC system that has an automated sanitization capability. Implement and document a procedure that utilizes this capability to sanitize the CODEC when transitioning between networks. As a last resort, implement and document a manual sanitization / reconfiguration procedure to perform this function.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49176r5_chk'
  tag severity: 'medium'
  tag gid: 'V-43019'
  tag rid: 'SV-55748r1_rule'
  tag stig_id: 'RTS-VTC 7080'
  tag gtitle: 'RTS-VTC 7080 [IP]'
  tag fix_id: 'F-48603r4_fix'
  tag 'documentable'
  tag severity_override_guidance: 'This can be downgraded from a CAT II to a CAT III if a manual procedure is used to perform a factory reset and/or overwrite all configurable parameters with null settings before reconfiguring the CODEC for connection to the next network.'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCSS-2, ECSC-1'
end
