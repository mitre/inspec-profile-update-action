control 'SV-16732' do
  title 'USB drives automatically load when inserted into the ESX Server host.'
  desc 'External USB drives may be inserted into the ESX Server and be loaded automatically on the service console. The USB drive will still need to be mounted, but drivers are loaded to recognize the device. Malicious users may be able to run malicious code on the ESX Server and go undetected since the USB drive is external. Therefore, USB drives will not be loaded automatically within the ESX Server.'
  desc 'check', 'At the ESX Server service console terminal, type the following:
# grep usb /etc/modules.conf

Verify that all “alias usb-controller“ text is commented out with a pound sign (#). 

Text should look similar to the following:
# alias usb-controller usb-uhci
# alias usb-controller1 usb-ohci

If not, this is a finding.

Caveat: This is not applicable to usb keyboards and mice that are plugged into the system.  If this is the case, this check is Not Applicable.'
  desc 'fix', 'Disable the external USB drive from loading automatically.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-15980r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15793'
  tag rid: 'SV-16732r1_rule'
  tag stig_id: 'ESX0110'
  tag gtitle: 'USB drives automatically load on ESX Server host.'
  tag fix_id: 'F-15735r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
