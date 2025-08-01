control 'SV-234156' do
  title 'The FortiGate firewall must be configured to inspect all inbound and outbound traffic at the application layer.'
  desc 'Application inspection enables the firewall to control traffic based on different parameters that exist within the packets such as enforcing application-specific message and field length. Inspection provides improved protection against application-based attacks by restricting the types of commands allowed for the applications. Application inspection enforces conformance against published RFCs.

Some applications embed an IP address in the packet that needs to match the source address that is normally translated when it goes through the firewall. Enabling application inspection for a service that embeds IP addresses, the firewall translates embedded addresses and updates any checksum or other fields that are affected by the translation. Enabling application inspection for a service that uses dynamically assigned ports, the firewall monitors sessions to identify the dynamic port assignments, and permits data exchange on these ports for the duration of the specific session.'
  desc 'check', 'Log in to the FortiGate CLI with Super-Admin privilege, and then run the command:
# show system session-helper.

Review the output and ensure it matches the following:
config system session-helper
    edit 1
        set name pptp
        set protocol 6
        set port 1723
    next
    edit 2
        set name h323
        set protocol 6
        set port 1720
    next
    edit 3
        set name ras
        set protocol 17
        set port 1719
    next
    edit 4
        set name tns
        set protocol 6
        set port 1521
    next
    edit 5
        set name tftp
        set protocol 17
        set port 69
    next
    edit 6
        set name rtsp
        set protocol 6
        set port 554
    next
    edit 7
        set name rtsp
        set protocol 6
        set port 7070
    next
    edit 8
        set name rtsp
        set protocol 6
        set port 8554
    next
    edit 9
        set name ftp
        set protocol 6
        set port 21
    next
    edit 10
        set name mms
        set protocol 6
        set port 1863
    next
    edit 11
        set name pmap
        set protocol 6
        set port 111
    next
    edit 12
        set name pmap
        set protocol 17
        set port 111
    next
    edit 13
        set name sip
        set protocol 17
        set port 5060
    next
    edit 14
        set name dns-udp
        set protocol 17
        set port 53
    next
    edit 15
        set name rsh
        set protocol 6
        set port 514
    next
    edit 16
        set name rsh
        set protocol 6
        set port 512
    next
    edit 17
        set name dcerpc
        set protocol 6
        set port 135
    next
    edit 18
        set name dcerpc
        set protocol 17
        set port 135
    next
    edit 19
        set name mgcp
        set protocol 17
        set port 2427
    next
    edit 20
        set name mgcp
        set protocol 17
        set port 2727
    next
end

If the output does not match, this is a finding.'
  desc 'fix', 'Fix can be performed on FortiGate CLI. For any modified or missing session-helpers, log in to the FortiGate console via SSH or console access and run the following commands:

   # config system session-helper
   #    edit {integer}
   #    set name {name of protocol}
   #    set protocol {protocol number}
   #    set port {port number}
   # next
   # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37341r611466_chk'
  tag severity: 'medium'
  tag gid: 'V-234156'
  tag rid: 'SV-234156r628776_rule'
  tag stig_id: 'FNFG-FW-000135'
  tag gtitle: 'SRG-NET-000364-FW-000040'
  tag fix_id: 'F-37306r611467_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
