control 'SV-234202' do
  title 'The FortiGate device must authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.'
  desc 'If NTP is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command: 
     # diagnose sys ntp status

The output should be similar to:
          ipv4 server(URL of NTP server) 123.123.123.123 -- reachable(0xbf) S:1 T:242 selected
          server-version=4, stratum=2
          reference time is e213a5fb.2250b45e -- UTC Wed Mar 11 18:01:31 2020
          clock offset is 0.000801 sec, root delay is 0.000381 sec
          root dispersion is 0.053268 sec, peer dispersion is 287 msec

If the output does not return server-version is equal to 4, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command: 

     # config system ntp
     #    set ntpsync enable
     #    set type custom
     #    set syncinterval {INTEGER}
     # config ntpserver
     #    edit {ID}
     #    set server {IP ADDRESS}
     #    set authentication enable
     #    set key {PASSWORD}
     #    set key-id {INTEGER}
     #    next
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37387r611793_chk'
  tag severity: 'medium'
  tag gid: 'V-234202'
  tag rid: 'SV-234202r850533_rule'
  tag stig_id: 'FGFW-ND-000215'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-37352r611794_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
