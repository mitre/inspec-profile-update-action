control 'SV-55747' do
  title 'An IP-based VTC system implementing a single CODEC supporting conferences on multiple networks having different classification levels (i.e., unclassified, SECRET, TOP SECRET, TS-SCI) must support Periods Processing sanitization by purging/clearing volatile memory within the CODEC by powering the CODEC off for a minimum of 60 seconds.'
  desc 'Volatile memory requires power to maintain the stored information. It retains its contents while powered, but when power is interrupted, stored data is immediately lost. Dynamic random-access memory (DRAM) is a type of random-access memory that stores each bit of data in a separate capacitor within an integrated circuit. Since capacitors leak charge, data fades unless the capacitor charge is refreshed periodically. Static random-access memory (SRAM) has a different configuration from DRAM which allows it to retain data longer when power is no longer applied (data remanence). Powering off the CODEC for 60 seconds is sufficient to discharge the capacitors and erase all data.'
  desc 'check', 'Observe the operation of the VTC system as it transitions between networks. Verify that the CODEC is powered off for a minimum of 60 seconds during the transition.  If it is not, this is a finding.'
  desc 'fix', 'Sanitize volatile memory by disconnection of all power for at least 60 seconds.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49175r3_chk'
  tag severity: 'medium'
  tag gid: 'V-43018'
  tag rid: 'SV-55747r1_rule'
  tag stig_id: 'RTS-VTC 7060'
  tag gtitle: 'RTS-VTC 7060 [IP]'
  tag fix_id: 'F-48602r5_fix'
  tag 'documentable'
  tag ia_controls: 'DCCS-2, ECSC-1'
end
