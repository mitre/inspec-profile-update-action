control 'SV-234183' do
  title 'The FortiGate device must synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command: 
     # show full-configuration system ntp | grep source-ip

The output should be:
           set source-ip {IP address of NTP server 1}
           set source-ip {IP address of NTP server 2}

If the internal information system clocks are not configured to synchronize with the primary and secondary time sources, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command: 

     # config system ntp
     #    set ntpsync enable
     #    set type custom
     #    set syncinterval {INTEGER}
To add NTP server 1:
     # config ntpserver
     #    edit {ID}
     #    set server {IP ADDRESS}
     #    set authentication enable
     #    set key {PASSWORD}
     #    set key-id {INTEGER}
     #    next
To add NTP server 2:
     # config ntpserver
     #    edit {ID}
     #    set server {IP ADDRESS}
     #    set authentication enable
     #    set key {PASSWORD}
     #    set key-id {INTEGER}
     #    next
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate NDM'
  tag check_id: 'C-37368r611736_chk'
  tag severity: 'medium'
  tag gid: 'V-234183'
  tag rid: 'SV-234183r628777_rule'
  tag stig_id: 'FGFW-ND-000120'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-37333r611737_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
