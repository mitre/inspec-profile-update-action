control 'SV-4632' do
  title 'Laptops with WLAN interfaces must have the WLAN card radio set to OFF as the default setting.'
  desc 'Laptop computers with wireless interfaces particularly susceptible to the Windows XP wireless vulnerabilities.  If a user has an active wireless interface with security disabled, a hacker could connect to the laptop without the user being aware of the connection.  Most laptop vendors provide a software utility to manage WLAN connections for the embedded wireless interfaces.  The utility usually provides a feature that allows a laptop user to turn off the WLAN radio.'
  desc 'check', "NOTE:  This requirement does not apply to tactical WLAN systems where the WLAN client is configured to connect to only specific tactical access point(s).

Have the SA or IAO demonstrate the configuration of the WLAN interface in the interface's management utility.  
1. Observe that the interface is set to off by default upon boot-up of the WLAN client device.  
2. Verify this is standard practice by checking a sample of WLAN laptops/PDAs (at least 2-3 should be checked).  Laptops can be checked by verifying the status of the wireless interface upon boot-up in each profile used on the laptop. 
3. Verify users have been trained on this requirement by reviewing the site training records and the signed User Agreement. 
4. Mark as a finding any of the following is found:
- The WLAN radio functionality (transmit/receive setting) is enabled upon system boot.
- If the WLAN interface management utility does not provide the ability to set the radio to OFF by default.
-  Users have not received required training on how to disable a wireless interface."
  desc 'fix', 'Change the default setting on each WLAN interface to OFF and train users on how to disable wireless interfaces after they are no longer in use.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-16040r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4632'
  tag rid: 'SV-4632r1_rule'
  tag stig_id: 'WIR0180'
  tag gtitle: 'Default OFF setting on wireless interfaces'
  tag fix_id: 'F-6765r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
